# strongSwan Rust kernel backend

This repository builds independently of strongSwan. `kernel-rust` replaces
charon's `kernel-netlink` plugin with a C proxy and a
Rust process, `charon-kernel-daemon`. They communicate using
[Varlink](https://varlink.org/) over Unix stream sockets. The Rust daemon
implements Linux XFRM and link operations directly; it never loads the C
netlink backend. The canonical API is [io.ranet.Kernel.varlink](io.ranet.Kernel.varlink).

The scope follows [ranet's VICI configuration](https://github.com/NickCao/ranet/blob/b0e52359f7c5816263f83cd5f12065945c5e4eaa/src/vici.rs):
tunnel-mode ESP, nonzero XFRM interface IDs, forced UDP encapsulation, high
IKE ports, IPv4/IPv6 selectors, SA output marks, statistics, expiry events,
and CHILD_SA rekeying. Both default ESP proposals (including AES-GCM and
AES-CBC with HMAC) and ESN are supported. MOBIKE, transport/BEET mode, AH,
IPComp, IP-TFS, hardware offload, labels, virtual IPs, and host route/rule
installation are outside this backend's scope. The C adapter rejects these
features instead of silently changing their behavior.

An interface named `ranet<if_id in eight hex digits>` is created and brought
up **before its first SA is installed**. Its default MTU is 1400. Every SA
using that ID shares the interface, including inbound/outbound SAs and old/new
SAs during rekeying. Removing or hard-expiring the final SA deletes the
interface. A failed first installation rolls it back. Policies alone do not
retain an interface. Existing interfaces are never adopted or deleted.
`--ifname-prefix` and `--mtu` change the naming prefix and MTU.

Remove ranet's interface creation/deletion updown script. Keep its
`if_id_in = %unique` and `if_id_out = %unique` settings. Those produce a
shared ID for both directions; `%unique-dir` also works when separate
interfaces are wanted. Route/address configuration for the overlay remains
with the network configuration, using the daemon-created interface names.
There are no interface creation/deletion RPCs exposed to charon.

## Build with Meson

The standalone build needs a C compiler, Meson 1.1 or newer, Ninja,
pkg-config, and Jansson development headers (`libjansson-dev` on Debian).
Building the daemon also needs Cargo/Rust 1.85 or newer; its dependencies are
pinned in `Cargo.lock`.

The plugin must use the **source headers and generated config.h matching the
installed strongSwan**, including its version, build options, and distribution
patches. It uses charon's C interfaces, so it is not a version-independent
binary. StrongSwan's installed development headers only cover libstrongswan;
they do not supply the libcharon kernel interfaces. Obtain both trees from
the package's matching source/build artifacts, or from your own strongSwan
build. Meson reads them without modifying or building strongSwan.

```sh
meson setup build \
    -Dstrongswan_source=/absolute/path/to/strongswan-source \
    -Dstrongswan_build=/absolute/path/to/strongswan-build \
    --prefix=/usr \
    -Dplugin_dir=/usr/lib/ipsec/plugins
meson compile -C build
meson test -C build
meson install -C build
```

For an in-source strongSwan build, omit `strongswan_build`; it defaults to
`strongswan_source`. Set `plugin_dir` to the installed strongSwan plugin
location. Its default is Meson's `libdir` plus `ipsec/plugins`, which may
differ from a distribution's layout. The daemon installs under
`libexecdir/ipsec/charon-kernel-daemon`. `-Dpiddir=/run` controls the plugin's
default socket location, independently of the installation prefix.

Meson builds the C module as `libstrongswan-kernel-rust.so` and calls Cargo
with `--locked --release` for the daemon. It does not link a second copy of
strongSwan's libraries into the plugin; the existing daemon supplies the host
symbols when it loads the module. No libtool `.la` file, core patch, or
`--enable-kernel-rust` strongSwan configure option is needed.

Build only the plugin without a Rust toolchain by passing `-Ddaemon=false`.
Build only the daemon with `-Dplugin=false`; this does not require strongSwan
headers. The normal Cargo workflow remains available:

```sh
cargo build --locked --release
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Use Meson's native/cross files for plugin toolchains. For a cross build, set
`-Ddaemon=false` and build the daemon separately with Cargo for that target.
Meson's installation supports `DESTDIR` for packaging:

```sh
DESTDIR=/tmp/kernel-rust-package meson install -C build
```

The build does not install or enable a strongswan.conf fragment. Enable the
plugin explicitly in the existing configuration after starting the daemon.
Rebuild the plugin when upgrading or changing the host strongSwan build.

## Run

The daemon needs `CAP_NET_ADMIN` in the relevant network namespace and
permission to set the socket owner/group (normally root with CAP_CHOWN). Charon
needs no capabilities when started as its final user, using writable runtime
and credential directories and UDP ports at least 1024. It binds its own
sockets and configures UDP_ENCAP/UDP_GRO locally. The daemon installs global
UDP port bypass policies for IKE. There is **no descriptor passing** and no
privileged bind operation. Do not configure `socket-default.fwmark`, which
would require SO_MARK on charon's sockets; ranet's `set_mark_out` applies to
SAs and is supported by the daemon.

For charon UID/GID 1000, run the daemon in the same network namespace:

```sh
charon-kernel-daemon --socket /run/charon-kernel.sock --uid 1000 --gid 1000
```

The socket's parent directory must permit the charon user to traverse it and
must prevent untrusted users replacing its entries. The daemon refuses to
unlink an existing socket path. It defaults to root as the permitted client;
`--uid` selects the charon user. Root is also accepted. `--gid` sets the
socket group. The plugin verifies the daemon's UID (root by default); set
`daemon_uid` if the daemon runs as another user with CAP_NET_ADMIN.

Example strongswan.conf excerpt, with ranet's endpoint port set to 13000:

```ini
charon {
    load_modular = yes
    port = 13001
    port_nat_t = 13000
    install_routes = no
    plugins {
        kernel-netlink {
            load = no
        }
        kernel-rust {
            load = yes
            socket = /run/charon-kernel.sock
            daemon_uid = 0
        }
    }
}
```

Keep socket-default and the normal authentication/crypto/VICI plugins loaded.
If you use an explicit `charon.load` list instead of modular loading, add
`kernel-rust` to that list and remove `kernel-netlink`.
Start charon as its unprivileged user with all capability sets removed; the
integration test below includes an executable example. The daemon has a
separate lifetime from charon. SA keys travel over the private socket and
are never returned by query methods. Binary key buffers and Netlink buffers
are wiped on release; JSON libraries may make transient copies. Core dumps
are disabled in the daemon. Avoid tracing RPC payloads.

## Session and recovery behavior

The daemon serves one charon session at a time. An independently authenticated
second connection from the same PID/UID carries Varlink streaming events.
A clean close requires all tunnel SAs/policies removed, cleans larval SPI
reservations and IKE bypass policies, and permits a new session. Flushes are
restricted to session-owned objects; flushing tunnel policies preserves IKE
port bypasses until close.

If charon or its event connection disappears unexpectedly, installed tunnel
objects are preserved and replacement sessions are rejected. Hard expiry
still releases the last SA's interface. Automatic restart reconciliation
and ownership persistence across daemon restarts are not implemented. Endpoint
or encapsulation migration requires reestablishing the SAs. This
is an experimental backend with a coordinated restart requirement: stop
protected traffic before removing leftover objects and restarting the pair.
Routes through deleted interfaces disappear with the links.

## Verification

Tested with an unmodified strongSwan 6.1.0 checkout, with the plugin and
daemon built and installed solely through this repository's Meson build.
The tunnel test needs an installed disposable strongSwan prefix containing
the separate plugin and daemon. It requires root, iproute2, OpenSSL, ping,
setpriv, and the Python VICI library. Install that library, or point
`--vici-python` at the one shipped with strongSwan. Tests create disposable
network namespaces and leave the caller's network namespace untouched:

```sh
unshare --net -- python3 tests/integration.py build/charon-kernel-daemon
unshare --net -- python3 tests/tunnel.py /tmp/strongswan-install \
    --vici-python /path/to/strongswan/src/libcharon/plugins/vici/python
unshare --net -- python3 tests/tunnel.py /tmp/strongswan-install --cbc \
    --vici-python /path/to/strongswan/src/libcharon/plugins/vici/python
```

The RPC test checks standard introspection (also with varlinkctl when
installed), a capability-free client, validation, interface rollback,
foreign objects, overlapping SAs, scoped flushes, larval allocation, hard
expiry, and expiry after losing the client. The tunnel tests use
capability-free charons, Ed25519 raw public keys, ranet's wildcard IPv4/IPv6
selectors, high ports, output marks, traffic counters, actual rekeying with
stable interface indices, and final-SA interface deletion. The default run
negotiates default ESP proposals; the second forces AES-CBC/HMAC-SHA256
with ESN.

## License and origin

The source is licensed GPL-2.0-or-later. `COPYING` is the unchanged GPL v2
license text copied from strongSwan's `COPYING`. The Rust XFRM and network
implementation was ported from strongSwan's kernel-netlink backend; the
source headers identify that origin and its upstream authors.
