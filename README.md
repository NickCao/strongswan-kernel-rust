# strongSwan Rust kernel backend

This repository builds independently of strongSwan. `kernel-rust` replaces
charon's `kernel-netlink` plugin with a Rust `cdylib` and a
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
installation are outside this backend's scope. The plugin rejects these
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

## Build with Cargo and cargo-c

The repository pins Rust **1.99.1** with `rust-toolchain.toml`. This provides
stable C variadic functions and `std::ffi::VaList` for strongSwan's enumerators,
including the 1.99.1 C ABI fixes. Both the plugin and daemon are implemented
in Rust; no C shim or Jansson is used. The small `plugin/wrapper.h` is only
input to bindgen, which generates layouts from the host's headers.

Use [cargo-c](https://github.com/lu-zero/cargo-c) **0.10.26 or newer** to build
and install the unversioned plugin module. The build also needs a native
linker and libclang (`build-essential libclang-dev` on Debian). Installing
cargo-c from source additionally needs pkg-config and OpenSSL development
headers (`pkg-config libssl-dev`). Rust dependencies are pinned in `Cargo.lock`.

```sh
rustup toolchain install 1.99.1 --profile minimal --component rustfmt,clippy
cargo install cargo-c --version '0.10.26+cargo-0.100.0' --locked
```

The plugin must use the **source headers and generated config.h matching the
installed strongSwan**, including its version, build options, and distribution
patches. It uses charon's C interfaces, so it is not a version-independent
binary. StrongSwan's installed development headers only cover libstrongswan;
they do not supply the libcharon kernel interfaces. Obtain both trees from
the package's matching source/build artifacts, or from your own strongSwan
build. Bindgen reads them without modifying or building strongSwan.

```sh
export STRONGSWAN_SOURCE=/absolute/path/to/strongswan-source
export STRONGSWAN_BUILD=/absolute/path/to/strongswan-build
cargo cbuild -p strongswan-kernel-rust --release --locked --library-type=cdylib
cargo build -p charon-kernel-daemon --release --locked
cargo test --locked -p charon-kernel-daemon -p kernel-rust-protocol
cargo clippy --locked --workspace --all-targets -- -D warnings

# Install into the prefix containing the matching strongSwan.
cargo cinstall -p strongswan-kernel-rust --release --locked \
    --library-type=cdylib --prefix=/usr --libdir=lib
cargo install --locked --path . --root /usr
```

For an in-source strongSwan build, omit `STRONGSWAN_BUILD`; it defaults to
`STRONGSWAN_SOURCE`. `IPSEC_PIDDIR` defaults to `/run` and controls the plugin's
default socket location independently of the installation prefix.

cargo-c installs `libstrongswan-kernel-rust.so` under
`<prefix>/<libdir>/ipsec/plugins`, with the same unversioned SONAME. Select
`--libdir` to match the host's layout; an absolute libdir overrides the prefix.
Plugin mode installs only the shared module, without headers, static libraries,
or pkg-config files. The existing charon supplies its host symbols at `dlopen`;
the module does not link another copy of strongSwan's libraries. No libtool
`.la` file, core patch, or `--enable-kernel-rust` configure option is needed.

`cargo install --path .` installs the daemon in `<root>/bin`. Building only the
daemon requires no strongSwan headers or libclang. Plain `cargo build` also
builds the Rust module with `-p strongswan-kernel-rust`; cargo-c handles its
loader filename, SONAME, and installation. There are no Meson files or custom
Python build scripts.

For packaging, cargo-c supports `--destdir`. Stage the daemon with the standard
`install` utility:

```sh
cargo cinstall -p strongswan-kernel-rust --release --locked \
    --library-type=cdylib --prefix=/usr --libdir=lib \
    --destdir=/tmp/kernel-rust-package
install -Dm755 target/release/charon-kernel-daemon \
    /tmp/kernel-rust-package/usr/bin/charon-kernel-daemon
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
daemon built and installed independently through Cargo/cargo-c.
The tunnel test needs an installed disposable strongSwan prefix containing
the separate plugin and daemon. It requires root, iproute2, OpenSSL, ping,
setpriv, and the Python VICI library. Install that library, or point
`--vici-python` at the one shipped with strongSwan. Tests create disposable
network namespaces and leave the caller's network namespace untouched:

```sh
unshare --net -- python3 tests/integration.py target/release/charon-kernel-daemon
unshare --net -- python3 tests/plugin.py /tmp/strongswan-install
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
stable interface indices, and final-SA interface deletion. The ABI test uses
the stock strongSwan 6.1 function tables to exercise both variadic `enumerate`
and C `va_list` forwarding to Rust's `venumerate`, with IPv4/IPv6 addresses and
subnets, plus repeated clean sessions and descriptor cleanup. The default tunnel run
negotiates default ESP proposals; the second forces AES-CBC/HMAC-SHA256
with ESN.

## License and origin

The source is licensed GPL-2.0-or-later. `COPYING` is the unchanged GPL v2
license text copied from strongSwan's `COPYING`. The Rust XFRM and network
implementation was ported from strongSwan's kernel-netlink backend; the
source headers identify that origin and its upstream authors.
