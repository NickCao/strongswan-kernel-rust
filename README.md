# strongSwan Rust kernel backend

This repository builds independently of strongSwan. `kernel-rust` replaces
charon's `kernel-netlink` plugin with a Rust `cdylib` and a
Rust process, `charon-kernel-daemon`. They communicate using
[tarpc](https://docs.rs/tarpc/) over Unix stream sockets. The Rust daemon
implements Linux XFRM and link operations directly; it never loads the C
netlink backend. Netlink transport uses `neli`; typed network and XFRM payloads
use `netlink-packet-route` and `netlink-packet-xfrm`. The canonical API is
[protocol/src/lib.rs](protocol/src/lib.rs).

The daemon exclusively owns **all global XFRM policies and the XFRM state table
in its network namespace**, including objects for other transform protocols.
Unwanted installed states and global policies are removed. Run other IPsec
managers in a separate network namespace. Session startup, `FlushSas`, and
orderly daemon shutdown flush the entire state table, including larval SPI
reservations. Per-socket policies remain owned by their sockets.

The scope follows [ranet's VICI configuration](https://github.com/NickCao/ranet/blob/b0e52359f7c5816263f83cd5f12065945c5e4eaa/src/vici.rs):
tunnel-mode ESP, nonzero XFRM interface IDs, forced UDP encapsulation, high
IKE ports, IPv4/IPv6 selectors, SA output marks, statistics, expiry events,
and CHILD_SA rekeying. Both default ESP proposals (including AES-GCM and
AES-CBC with HMAC) and ESN are supported. MOBIKE, transport/BEET mode, AH,
IPComp, IP-TFS, hardware offload, labels, virtual IPs, and host route/rule
installation are outside this backend's scope. The daemon rejects unsupported SA and policy options. The plugin forwards
all input fields, including options that future backends may support.

The backend advertises `KERNEL_REQUIRE_UDP_ENCAPSULATION`, so charon forces
ESP-in-UDP for its connections. Existing `encap=yes` configurations behave
the same.

Linux XFRM handles ESPv3 TFC padding, controlled by the CHILD_SA's
`tfc_padding` setting (disabled by default). On Linux 6.2 and later, the
backend also advertises `KERNEL_SA_USE_TIME`: SA queries return the last use
time converted from the kernel's Unix timestamp to strongSwan's monotonic
clock. Earlier kernels use strongSwan's policy-query fallback.

An interface named `ranet<if_id in eight hex digits>` is created and brought
up **before its first SA is installed**. Its default MTU is 1400. Every SA
using that ID shares the interface, including inbound/outbound SAs and old/new
SAs during rekeying. Removing or hard-expiring the final SA deletes the
interface. A failed first installation rolls it back. Policies alone do not
retain an interface. Linux link group **17227** is reserved for daemon-owned
interfaces; `--interface-group` selects a different nonzero numeric group.
Every interface in that group is owned, regardless of its native type or name.
Group membership selects the interfaces returned by the ownership inventory.
It persists across daemon restarts and needs no entry in iproute2's group names file.
Independent daemon instances require separate network namespaces because each
owns its global policy table. `--ifname-prefix` and `--mtu` change the naming
prefix and MTU. Interfaces have multicast enabled. `--master-device NAME` attaches them to an existing
master, such as a VRF, before installing the first SA. Without this option,
the standalone daemon leaves them unattached. The master remains owned by
the network configuration and is never created or deleted by the daemon.

Remove ranet's interface creation/deletion updown script. Keep its
`if_id_in = %unique` and `if_id_out = %unique` settings. Those produce a
shared ID for both directions; `%unique-dir` also works when separate
interfaces are wanted. Route/address configuration for the overlay remains
with the network configuration, using the daemon-created interface names.
There are no interface creation/deletion RPCs exposed to charon.

## Build with Nix

The flake provides packages for `x86_64-linux` and `aarch64-linux`:

```sh
nix build                         # daemon and plugin
nix build .#charon-kernel-daemon  # daemon alone, without strongSwan headers
nix build .#strongswan            # matching strongSwan for NixOS
nix develop                      # Cargo/cargo-c shell with both header paths set
nix flake check -L               # package checks and a two-machine NixOS VM test
```

`flake.lock` pins nixpkgs and the Rust overlay. The toolchain follows
`rust-toolchain.toml`. The flake supplies a recent cargo-c and prepares a
header tree and `config.h` using the strongSwan package's source, patches,
dependencies, and configure flags. No manual header paths are needed.

Import `kernel-rust.nixosModules.default` from the flake into your NixOS
configuration and set `services.charon-kernel.enable = true`. For example:

```nix
services.charon-kernel = {
  enable = true;
  mtu = 1400;
  interfaceNamePrefix = "ranet";
  interfaceGroup = 17227;
  masterDevice = "gravity";
};
```

The MTU accepts 1280–65535 and the prefix accepts 1–7 ASCII letters, digits,
underscores, or hyphens. The module defaults `masterDevice` to `gravity`;
that interface must exist before the first CHILD_SA is installed. For example,
create the VRF with networkd:

```nix
systemd.network = {
  enable = true;
  netdevs."20-gravity" = {
    netdevConfig = {
      Name = "gravity";
      Kind = "vrf";
    };
    vrfConfig.Table = 42;
  };
  networks."20-gravity" = {
    matchConfig.Name = "gravity";
    networkConfig.LinkLocalAddressing = "no";
  };
};
```

The module adds
the daemon, plugin, and matching strongSwan to `environment.systemPackages`,
links `/lib/ipsec/plugins` into the system profile, and selects the matching
package for `services.strongswan-swanctl`. The strongSwan package uses
`--with-plugindir=/run/current-system/sw/lib/ipsec/plugins`, so external
plugins in the system profile are discoverable. Installation overrides
`plugindir` to the package's `lib/ipsec/plugins` directory. EAP plugins are
disabled; ranet uses public-key authentication. `--with-piddir=/run/strongswan`
sets the default VICI socket to `/run/strongswan/charon.vici`, so `swanctl`
needs no `--uri` flag. The module lets systemd create that directory when the
IKE service is enabled.

The module enables `services.strongswan-swanctl` with a dynamic user and no
capabilities. The kernel daemon runs as a
separate dynamic user with only `CAP_NET_ADMIN`. Both services use the static
`ipsec` group for their sockets; change it with `services.charon-kernel.group`.
Systemd manages their runtime directories.

The module applies a shared systemd sandbox to both services: a read-only
filesystem with private temporary directories and devices, private IPC,
hidden foreign processes and global `/proc` files, no writable executable
memory, and a native syscall allow list excluding kernel keyring operations.
Realtime scheduling is blocked and core dump limits are zero. Runtime
directories use mode 0750 and the static access group. Charon permits Unix,
IPv4, IPv6 and Netlink sockets; the kernel daemon permits only Unix and
Netlink sockets.

StrongSwan pulls in the kernel service with `BindsTo` and `After` and waits
for its readiness notification after the socket is ready. `PartOf` propagates
strongSwan stops/restarts to the daemon, with strongSwan stopping first so it
can remove its SAs. `StopWhenUnneeded` also stops the daemon if IKE exits on
its own. Losing the kernel daemon stops IKE. The kernel daemon starts only as
a dependency of IKE.

The module does not write strongSwan configuration or firewall rules.
Use `services.strongswan-swanctl.strongswan.extraConfig` and `swanctl` to
configure plugins, ports, and peers. Enable `kernel-rust`, disable
`kernel-netlink`, and use high UDP ports for the unprivileged IKE service.
For example, with `config` in your NixOS module arguments:

```nix
networking.firewall.allowedUDPPorts = [ 13000 ];
services.strongswan-swanctl.strongswan.extraConfig = ''
  charon {
    port = 0
    port_nat_t = 13000
    install_routes = no
    load_modular = yes
    plugins {
      include ${config.services.strongswan-swanctl.package}/share/strongswan/templates/config/plugins/*.conf
      kernel-netlink { load = no }
      kernel-rust { load = yes }
    }
  }
'';
```

Modular loading is needed because the standalone plugin is absent from
strongSwan's compile-time plugin list. Include the package-generated snippets
to retain its enabled plugins without maintaining a global `load` list.

The VM check uses actual strongSwan `charon-systemd` processes with dynamic
users and no capabilities, alongside the restricted dynamic kernel daemons.
It checks plugin discovery from the system profile, socket authorization,
the kernel RPC contract regressions in an isolated network namespace,
AES-GCM and AES-CBC/HMAC, TFC padding, encrypted IPv4/IPv6 traffic,
SA use times that age while idle and reset after traffic, rekeying without
interface replacement, final-SA cleanup, configurable interface names/MTUs/groups,
default and custom VRF masters, multicast flags, VRF-routed IPv4/IPv6 traffic,
VICI responsiveness with 200 connections and continuous BGP-style route updates,
VICI access from a separate dynamic controller, coordinated stop/restart,
startup failure, daemon failure, and runtime directory removal.
The test requires KVM on the build host. Run it directly with:

```sh
nix build .#checks.x86_64-linux.end-to-end -L
```

See [nix/test.nix](nix/test.nix) for the peer configuration and
[nix/module.nix](nix/module.nix) for the kernel service's restrictions.

For integration with [gravity](https://github.com/NickCao/flakes/blob/master/modules/gravity/default.nix),
use `interfaceNamePrefix = "gn"` and `group = "strongswan"` to preserve its
interface naming and ranet group membership. Pass
`--vici=/run/strongswan/charon.vici` to ranet. Replace gravity's static charon
user, ambient network capability, and `SecureBits` setting with this module's
service setup, and remove the updown script that creates/deletes interfaces.
The daemon attaches interfaces to the existing `gravity` VRF (the module's
default `masterDevice`), enables multicast, and sets the MTU. Networkd no
longer needs to perform that attachment or enable multicast. Keep overlay
addresses, routes, and the VRF itself in the network configuration, and keep
gravity's IP-TFS option disabled. This describes the integration changes;
the VM check exercises the backend and shared VICI access, not gravity's
external registry and credential services.

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

The plugin takes two absolute paths: `STRONGSWAN_SOURCE` points to the full
strongSwan source tree, and `CONFIG_H_DIR` points to a directory containing
its generated `config.h`. That directory may contain just `config.h`, copied
from a matching configured strongSwan tree. Bindgen reads the headers and
configuration directly; no compiled strongSwan artifacts are needed.

Both inputs must match the **installed strongSwan**, including its version,
build options, and distribution patches. The plugin uses charon's C interfaces,
so it is not a version-independent binary. StrongSwan's installed development
headers only cover libstrongswan; they do not supply the libcharon kernel
interfaces. Obtain the full source and `config.h` from the package's matching
artifacts, or from your own configured strongSwan tree.

```sh
export STRONGSWAN_SOURCE=/absolute/path/to/strongswan-source
export CONFIG_H_DIR=/absolute/path/to/config-directory
cargo cbuild -p strongswan-kernel-rust --release --locked --library-type=cdylib
cargo build -p charon-kernel-daemon --release --locked
cargo test --locked -p charon-kernel-daemon -p kernel-rust-protocol
cargo clippy --locked --workspace --all-targets -- -D warnings

# Install into the prefix containing the matching strongSwan.
cargo cinstall -p strongswan-kernel-rust --release --locked \
    --library-type=cdylib --prefix=/usr --libdir=lib
cargo install --locked --path . --root /usr
```

If `config.h` is in the source tree's root, omit `CONFIG_H_DIR`; it defaults to
`STRONGSWAN_SOURCE`. Changes to `config.h` automatically regenerate the bindings.
The plugin's default socket is `/run/charon-kernel/charon-kernel.sock`; change
it at runtime with `charon.plugins.kernel-rust.socket` and the daemon's
`--socket` option.

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

The daemon needs `CAP_NET_ADMIN` in the relevant network namespace. For an
unprivileged daemon, its socket access group must be its primary or
supplementary group. Charon
needs no capabilities when started as its final user, using writable runtime
and credential directories and UDP ports at least 1024. It binds its own
sockets and configures UDP_ENCAP/UDP_GRO locally. The daemon installs global
UDP port bypass policies for IKE. There is **no descriptor passing** and no
privileged bind operation. Do not configure `socket-default.fwmark`, which
would require SO_MARK on charon's sockets; ranet's `set_mark_out` applies to
SAs and is supported by the daemon.

Create a dedicated static group and grant the charon service membership:

```sh
groupadd --system ipsec
```

Run the daemon in the same network namespace as charon, with systemd managing
its runtime directory. For example, the daemon service can use:

```ini
[Service]
Type=notify
ExecStart=/usr/bin/charon-kernel-daemon --group ipsec
DynamicUser=yes
User=charon-kernel
Group=ipsec
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
NoNewPrivileges=yes
RuntimeDirectory=charon-kernel
RuntimeDirectoryMode=0750
```

The daemon does not create directories. The socket's parent directory must
permit the charon user to traverse it and prevent untrusted users replacing
its entries. The daemon refuses to unlink an existing socket path.
The socket remains owned by the daemon, has
mode **0660**, and uses the group selected by `--group NAME|GID` (default GID
0). Linux authorizes connections using filesystem permissions, including
supplementary groups. There is no configured charon UID. Control calls and
event polls share one connection and its session; there is no token or
second-connection authentication. The client trusts the protected socket path;
no daemon UID is configured or pinned.

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
            socket = /run/charon-kernel/charon-kernel.sock
        }
    }
}
```

Keep socket-default and the normal authentication/crypto/VICI plugins loaded.
If you use an explicit `charon.load` list instead of modular loading, add
`kernel-rust` to that list and remove `kernel-netlink`.
Start charon as its unprivileged user with all capability sets removed; the
integration test below includes an executable example.

For a systemd-managed strongSwan service, `DynamicUser=yes` works with a
[static socket access group](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#User=).
For example, add this to the `charon-systemd`
service, alongside its existing executable and configuration:

```ini
[Service]
DynamicUser=yes
Group=ipsec
CapabilityBoundingSet=
AmbientCapabilities=
RuntimeDirectory=strongswan
RuntimeDirectoryMode=0750
```

Keep the kernel daemon in a separate service. Its protected socket directory
and static access group allow systemd to allocate dynamic users to both
services. Configure VICI under the IKE service's runtime directory, for example
`unix:///run/strongswan/charon.vici`, and deliver keys through VICI or systemd
credentials. With the plain `charon` executable, also provide a writable,
isolated location for its compile-time PID file; the dynamic-user tunnel test
does this with a systemd-managed runtime directory mounted at `/run`.

The daemon has a separate lifetime from charon. SA keys travel over the private
socket and are never returned by query methods. Netlink uses neli's standard
buffers; these and library serialization copies are not guaranteed to be wiped.
Core dumps are disabled in the daemon. Avoid tracing RPC or Netlink payloads.

Route/link/address notifications are coalesced over 100 ms, retaining whether
addresses changed, so routing updates do not queue a roaming job for every
route. SA expiry, acquisition, and mapping events are delivered immediately.
Host route lookups query the kernel FIB directly and honor its routing policy.
A route through an excluded or XFRM interface is rejected. A caller-supplied
or FIB-selected source address may belong to another interface, including one
excluded from discovery; a successful route lookup is authoritative.
Discovered IKE addresses exclude link-local addresses and include down or
ignored interfaces only when explicitly requested.
Subnet nexthop queries for route installation are unsupported.
Interface/address discovery is cached until a link or address notification
invalidates it. Interface ownership checks always query the kernel.

## Safety boundaries

The daemon and shared protocol crate use `#![forbid(unsafe_code)]`, including
the RPC client and socket framing. Linux calls use safe library APIs.
[neli](https://docs.rs/neli/0.7.4/neli/)
handles Netlink sockets and headers, multipart replies, ACKs, sequence/PID
checks, and multicast notifications. Network discovery and XFRM interface
operations use [netlink-packet-route](https://docs.rs/netlink-packet-route/0.33.0/netlink_packet_route/).
XFRM requests, SA/policy replies, acquire messages, attributes, and byte order use
[netlink-packet-xfrm](https://docs.rs/netlink-packet-xfrm/0.5.0/netlink_packet_xfrm/).
`SA_DIR` uses its generic attribute extension; expiry parsing retains trailing
interface ID/mark attributes that its high-level expiry message omits.
The daemon translates kernel errors to errno replies. Closing a session drops
its notification routers and wakes the event workers.

tarpc generates typed clients and dispatch from the shared Rust service trait,
with Bincode over length-delimited Unix socket frames. Server frames wrap replies
or a typed `EventsReady` notification. Inputs use native integer
widths, including full-range `u64` lifetimes and counters, and byte vectors for
keys and security labels. Endpoints retain IP, port, IPv6 flow information and
scope ID. SA inputs include mode, selectors, interface restrictions, lifetime
jitter, compression, offload, CPU selection and all flags. Policy inputs retain
the complete associated ESP/AH/IPComp configuration. Capability checks run in
the daemon's adapter; the kernel CRUD and reconciliation implementations are
unchanged. Filesystem socket permissions authorize the connection, whose
session ownership and disconnect rules remain in this repository. Subnet
arithmetic uses `ipnet`, and daemon arguments use `clap`. Library buffers use their normal allocation and release
behavior. Install matching plugin and daemon builds; this internal binary RPC
contract does not support mixing versions.

The plugin shares one Tokio current-thread runtime and one Unix connection.
StrongSwan's synchronous callbacks call `Runtime::block_on()` on their own
calling threads. Tokio drives the RPC dispatch task during these calls and
coordinates concurrent callers without a mutex held over an entire RPC. No
plugin thread is created. Charon's shared watcher monitors that same socket for
readability. Its short callback suspends watching and queues a cancellable,
low-priority processor job. The job calls `NextEvents`, handles its batch after
returning from the runtime, and fairly requeues while batches remain. Once empty,
it stops and rearms the watcher. There is no periodic polling, separate event
connection, wakeup socket or client event queue. The runtime drops when the last
client reference is released.

See [the event delivery measurements](BENCHMARKS.md) for a comparison with the
Tokio-worker client and continuous current-thread polling.

The transport also wakes the job when an RPC reads ahead into a following frame,
or consumes an `EventsReady` notification while another call is active. This
covers notifications already buffered in userspace, which socket readiness
alone would miss. A coalesced local flag retains wakeups until the job fetches
events; it also handles notifications arriving during plugin initialization.

The plugin still implements strongSwan's C interfaces. Its remaining unsafe
code borrows C callback arguments, invokes host functions, manages the exported
C function tables and variadic enumerators, and configures UDP socket options.
Validation, RPC calls, counters, and snapshot construction run in safe Rust.
Owned and borrowed C objects use [foreign-types](https://docs.rs/foreign-types/0.5.0/foreign_types/)
to pair construction with the matching strongSwan destructor. The shared
client registry uses `Weak`/`Arc` instead of untyped C pointers.
The event job uses weak client ownership and cancellation; unloading removes
the watcher and joins active event dispatch before closing the session. Blocking
Rust RPCs never run inside the watcher's pthread-cancellable callback. Charon
destroys queued
jobs before unloading plugin libraries. No pointers or descriptors cross the RPC
connection.

## Session and recovery behavior

The daemon serves one charon session at a time, with control calls and event
polls on the same Unix connection. `NextEvents` immediately drains one queued
batch or returns an empty batch. The daemon's bounded event queue retains
notifications until the next poll; overflow invalidates the session. The
daemon pushes a coalesced `EventsReady` frame when a batch is available or a
pending roam reaches its 100 ms coalescing deadline. The next fetch rearms that
notification. The plugin drains batches at low priority; higher-priority work
can delay event delivery. Idle operation sends no periodic RPCs or heartbeats.
A transport failure disables the connection without replaying mutations.
A clean close requires all tunnel SAs/policies removed, cleans larval SPI
reservations and all remaining global policies, and permits a new session.
The `FlushSas` RPC clears desired SAs and flushes the whole state table. Flushing
tunnel policies clears their desired references and reconciles the whole policy table,
preserving desired IKE port bypasses until close. Opening a new session first
reconciles global policies against an empty desired set, flushes old SAs and SPI
reservations, and removes owned interfaces before accepting new requests.

On SIGTERM or SIGINT, the daemon stops accepting requests and disables session
mutations and repairs. It clears desired policies, including IKE bypasses, and
runs a final policy and interface reconciliation against empty desired sets.
It also flushes the entire XFRM state table, including untracked SAs and larval
SPI reservations. Cleanup also runs if no session opened or the last one closed.
Policy ownership covers the entire global table; interface ownership is
discovered from the configured link group. Interfaces outside that group remain
untouched. Failed deletions remain discoverable for retries. Cleanup runs
explicitly before exit; errors are reported and cause a nonzero exit status. Signals are
received through `nix::sys::signalfd` in the main loop, outside signal handlers.
Orderly strongSwan shutdown normally removes its SAs before closing the session.
SIGKILL, aborts and daemon crashes bypass shutdown cleanup.

While the session is connected, missing or changed desired policies are repaired
from the current desired policy records, including IKE port bypasses.
SA, policy and link notifications are coalesced over 100 ms, and an audit runs every five
seconds to catch missed notifications. An external `ip xfrm policy flush` is therefore
recoverable without replacing SAs or interfaces. Unchanged policies are not
rewritten; kernel-assigned indices, usage counters, timestamps, attribute order
and omitted default attributes are excluded from configuration comparisons.
Inventory and repairs hold the same backend lock as policy installation and
deletion, so a pending repair cannot restore an obsolete rekey template or a
policy that strongSwan has removed. Unsolicited global policies are deleted,
including native policy configurations outside the supported model.

Linux implementations live under `src/linux/`: SA, policy and interface trait
implementations are in `xfrm.rs`, `policy.rs` and `interfaces.rs`, alongside
network discovery and Netlink support. Shared controllers, traits and
model types remain at the top level.

The policy controller in `src/policy.rs` keeps desired policies and shared
references without retaining a handle or ownership cache. It canonicalizes
identities, selects the winning strongSwan `PolicyData` reference and resolves
its effective priority and protection
template into a `PolicySpec`. Its `PolicyKernel` trait provides
list/get/create/update/delete operations with opaque handles and normalized
`ObservedPolicy` values. The controller compares observed configuration and
decides repairs. Inventory returns backend-owned policies, including leftovers,
and each handle exposes its captured logical identity through `id()`. Matching
identities with changed or unrepresentable configuration are passed to
`update()`; the backend chooses repair or replacement. Unidentified, duplicate
and undesired entries are deleted. `get` looks up one logical identity directly,
including its usage and fresh handle, so requests do not dump the table.
`LinuxPolicies` implements CRUD and translates typed XFRM messages. It lists all
global policies, including native selectors, security contexts and policy types
outside our supported configuration model. These remain visible for cleanup.
Linux handles use the kernel policy index as their native key and capture the
logical identity when representable. XFRM additionally requires mark, interface
ID and policy type qualifiers for index lookups; these stay private to the
backend. Updates inspect the current native object and replace it when Linux
cannot update it in place. No index ranges or other ownership markers are used.
Another device backend can reuse the controller without implementing
reconciliation or strongSwan reference selection.

The interface controller in `src/interfaces.rs` derives desired interfaces from
the current SA ownership records, grouped by interface ID. `InterfaceSpec`
contains an opaque logical `InterfaceId` and an `InterfaceConfig` with the
SA binding (`if_id`), MTU, master, UP and multicast settings. The caller currently
assigns the same numeric value to the logical identity and SA binding, but they
are separate concepts: backends configure XFRM from `config.if_id`, never by
interpreting the logical ID. Missing interfaces are created and changed settings
are repaired. Unchanged links do not call `update()`. Repairs share the policy worker and
backend lock, so deleting the final SA or rolling back a failed installation
cannot race with recreation. Policies alone do not keep interfaces alive.
Repairs stop when the session disconnects; hard expiry still removes unused
interfaces.

Its separate `InterfaceKernel` trait provides only list/create/update/delete
operations. Listing returns every backend-owned object as an `ObservedInterface`
with optional configuration and an opaque handle. The handle's `id()` returns
its logical identity, when known, from the captured snapshot without I/O.
All managed configuration is exposed through `InterfaceConfig`; the controller
updates matching desired IDs when that configuration differs or is
unrepresentable. It creates missing ones and deletes unidentified, undesired
or duplicate owned objects.
An unrepresentable configuration with a known desired ID is passed to
`update()`; the backend chooses in-place repair or replacement.

`LinuxInterfaces` implements CRUD using typed route Netlink messages and owns
group membership and naming. It keeps only its Netlink connection and fixed
configuration; every listing derives ownership and identity from the kernel.
Names encode the opaque logical ID, independently of native `if_id` drift.
An unrecognizable name loses its logical identity: the owned object is deleted
and recreated when needed, both during normal operation and after restart.
Renaming to another valid encoded name changes the observed logical identity.
Changing the configured prefix can also cause replacement. Wrong native types
with recognizable identities are replaced inside `update()`. Neither the
backend nor the shared controller keeps an interface association or ownership
cache.

Linux handles contain the interface index and the logical ID decoded from the
name. The index is the native primary key: updates and deletion target the
current interface at that index, including after index reuse. Group membership
selects ownership during listing; mutations do not recheck group membership,
logical identity or previous XFRM settings. Updating reads the current link only
to decide whether in-place repair or replacement is needed. Moving a link out
of the reserved group excludes it from subsequent listings. Repairs modify only
managed attributes; user aliases, addresses, queue lengths, unrelated flags and
other unmanaged settings are preserved during in-place updates. Network
discovery remains Linux-specific.

Recreated links lose their unmanaged settings, including addresses and routes,
which must be reapplied by the external network configuration; the daemon only
restores managed link settings. This also applies to replacement after renaming.
The NixOS test exercises this with systemd-networkd managing tunnel addresses
and routes while preserving the daemon-managed master attachment.

The SA controller in `src/sa.rs` treats established SAs as immutable. Its
`SaKernel` trait provides inventory, direct lookup, first installation,
deletion, SPI allocation and bulk flush, with no established-SA update method.
`LinuxSas` keeps only its Netlink connection and kernel capabilities. Native
handles use the destination/SPI/protocol/family/mark lookup key (and source for
address-based transforms); Linux has no SA index. Interface IDs are observed
configuration, not separate GETSA/DELSA lookup namespaces.

After successful synchronous installation, the controller retains a canonical
snapshot of managed configuration, including crypto keys, and the observed
installation time. Snapshots normalize kernel algorithm aliases/defaults and
attribute order. They exclude usage counters, error statistics, acquire
sequence IDs, last-use times and live replay/sequence state. Keys are never
returned over RPC or logged, and snapshots are not persisted. Querying usage
reads one SA without dumping the table.

A successful inventory retires missing or changed SAs and deletes drifted or
unwanted installed states. It emits one hard-expiry notification per retired
SA; strongSwan's IKEv2 expiry path negotiates a fresh CHILD_SA, normally retaining
the IKE_SA. The daemon never repairs or recreates an established SA, and never
restores old keys with reset packet state. Failed/interrupted inventories do
not imply loss. Audits and installation/deletion share one lock. Retirement
notifications are batched so a large state flush does not overflow the event
queue; failed native cleanup is retried independently of notification delivery.

The final retired SA releases its interface immediately, withdrawing its routes
so BIRD can select another tunnel. Remaining SAs, including overlapping rekeys,
keep shared interfaces alive. Network configuration restores addresses/routes
when fresh SAs create an interface again. An external `ip xfrm state flush`
therefore triggers fresh negotiation, rather than silent SA reinstallation.

Larval SPI reservations remain distinct from established SAs. `update` is
accepted only to complete a recorded reservation; update-to-add is allowed if
that reservation expired before first installation. A repeated installation of
an established SA is rejected. Kernel acquisition placeholders remain until
their normal kernel timeout; startup, explicit flush and shutdown also clear
these objects, including ones without an addressable SPI. Live packet state is
not mirrored or restored by reconciliation.

If charon or its connection disappears unexpectedly, installed tunnel
objects are preserved and replacement sessions are rejected. Hard expiry
still releases the last SA's interface. Interface ownership survives daemon
restarts through the reserved group. A new session retires old SAs, SPI
reservations, global policies and owned interfaces before installing fresh
resources. This does not recover desired SAs or established IKE
sessions. Automatic full restart recovery is not implemented. Endpoint or
encapsulation migration requires reestablishing the SAs. This
is an experimental backend with a coordinated restart requirement: stop
protected traffic before removing leftover objects and restarting the pair.
Routes through deleted interfaces disappear with the links.

Full crash recovery is deferred. Proposed follow-up work is:

- If charon crashes while the daemon survives, retire the failed session,
  stop its repairs, and remove the namespace's SAs, policies and larval SPI
  reservations along with daemon-owned interfaces. Accept a replacement session
  only after cleanup succeeds. The SA controller already provides the bulk
  cleanup used at orderly shutdown and session startup.
- If the daemon crashes, systemd already stops charon, but the kernel objects
  can outlive both processes. Interfaces are discoverable by group, and all
  global policies and SAs are owned and retired at session startup. This cleanup
  is implemented; automatic coordination outside the supplied systemd module
  and recovery of a disconnected client remain future work.
- Reload connection configuration and negotiate fresh IKE/CHILD_SAs after
  cleanup. Preserving established SAs across crashes is outside this proposal.

Verification should kill charon and the daemon separately with active tunnels,
then check cleanup, successful tunnel reestablishment, and preservation of
interfaces outside the reserved group. Interrupted cleanup and recovery also need
coverage before automatic daemon-crash recovery is enabled.

## Verification

Tested with an unmodified strongSwan 6.1.0 checkout, with the plugin and
daemon built and installed independently through Cargo/cargo-c.
The tunnel test needs an installed disposable strongSwan prefix containing
the separate plugin and daemon. It requires root, iproute2, OpenSSL, ping,
setpriv, and the Python VICI library. Install that library, or point
`--vici-python` at the one shipped with strongSwan. Tests create disposable
network namespaces and leave the caller's network namespace untouched:

```sh
cargo build --release --locked --features test-client --bin kernel-rpc-test-client
unshare --net -- python3 tests/integration.py target/release/charon-kernel-daemon \
    target/release/kernel-rpc-test-client
# Privileged checks share the namespace and must run serially:
unshare --net -- cargo test --locked -p charon-kernel-daemon \
    -- --ignored --test-threads=1
unshare --net -- python3 tests/plugin.py /tmp/strongswan-install
unshare --net -- python3 tests/tunnel.py /tmp/strongswan-install \
    --vici-python /path/to/strongswan/src/libcharon/plugins/vici/python
unshare --net -- python3 tests/tunnel.py /tmp/strongswan-install --cbc \
    --vici-python /path/to/strongswan/src/libcharon/plugins/vici/python
# On a VM running systemd, exercise actual DynamicUser services too:
unshare --net -- python3 tests/tunnel.py /tmp/strongswan-install --dynamic-user \
    --vici-python /path/to/strongswan/src/libcharon/plugins/vici/python
```

The RPC test checks socket group permissions and a rejected nonmember,
typed tarpc calls through a test-only Rust client adapter, a
capability-free client, address scope/type filtering, multihomed source
selection and egress-interface exclusions, ICMP policy priorities, policy
deletion/modification/flush repair, unsolicited global policy cleanup, policy
cleanup after daemon SIGKILL, interface recreation and settings repair,
index reuse and ownership conflicts, numeric group ownership across native link
types, crash inventory cleanup, native if_id drift independent of
logical identity, preservation of unmanaged settings, rekey references and teardown, validation,
interface rollback, foreign objects, overlapping SAs, policy flushes (including missing policies),
SA loss and configuration drift retirement, route withdrawal, 300-SA flush
notifications, unwanted state cleanup, larval maturation including an expired
reservation, hard expiry, and expiry after losing the client. The NixOS tunnel
tests additionally exercise inbound/outbound state deletion, full state flush,
native configuration drift and loss during rekey with AES-GCM and AES-CBC/HMAC;
new SPIs and working traffic must return without replacing the IKE session or
charon process. The tunnel tests use
capability-free charons, Ed25519 raw public keys, ranet's wildcard IPv4/IPv6
selectors, high ports, output marks, traffic counters, actual rekeying with
stable interface indices, and final-SA interface deletion. The ABI test uses
the stock strongSwan 6.1 function tables to exercise both variadic `enumerate`
and C `va_list` forwarding to Rust's `venumerate`, with IPv4/IPv6 addresses and
subnets, complete IPv6 sockaddr round trips, plus repeated clean sessions and client/daemon descriptor and daemon
worker cleanup. The default tunnel run
negotiates default ESP proposals; the second forces AES-CBC/HMAC-SHA256
with ESN.
The `--dynamic-user` variant needs a system systemd instance and the existing
`nogroup` test group. It verifies distinct dynamically allocated UIDs/primary
GIDs, socket access through a supplementary group, and empty capability sets
in the actual charon processes. Its transient units and runtime directories
are removed on exit.

## License and origin

The source is licensed GPL-2.0-or-later. `COPYING` is the unchanged GPL v2
license text copied from strongSwan's `COPYING`. The Rust XFRM and network
implementation was ported from strongSwan's kernel-netlink backend; the
source headers identify that origin and its upstream authors.
