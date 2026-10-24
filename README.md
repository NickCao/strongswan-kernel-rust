# strongSwan Rust kernel backend

`kernel-rust` is a Rust plugin for strongSwan and a separate privileged
`charon-kernel-daemon`. The plugin supplies charon's kernel IPsec and network
interfaces. The daemon manages Linux XFRM and tunnel interfaces through Netlink;
the two processes communicate over a Unix socket using
[tarpc](https://docs.rs/tarpc/).

Charon can run without capabilities on high UDP ports. The daemon needs
`CAP_NET_ADMIN` in the same network namespace.

**The daemon exclusively owns all global XFRM policies and the entire XFRM
state table in that namespace.** Opening a session removes existing global
policies, flushes SAs and SPI reservations, and removes interfaces in the
configured ownership group. Unwanted installed states and global policies are
also removed during operation. Other IPsec managers need a separate network
namespace. Per-socket policies are excluded from this ownership.

## Supported configuration

- ESP in tunnel mode or IP-TFS/AGGFRAG mode, with nonzero XFRM interface IDs.
- IPv4 and IPv6 outer addresses and traffic selectors, including wildcard
  selectors, CIDR subnets and aligned port ranges.
- Encryption and integrity algorithms mapped in
  [src/linux/xfrm.rs](src/linux/xfrm.rs), including AES-GCM,
  AES-CBC/HMAC and ChaCha20-Poly1305. strongSwan selects the algorithms;
  the running kernel determines availability.
- ESN, replay windows, lifetimes, SA output marks, TFC padding and ICMP error
  forwarding.
- SA/policy usage queries, expiry/acquire/NAT mapping events and CHILD_SA rekeying.

The IPsec backend advertises `KERNEL_REQUIRE_UDP_ENCAPSULATION`, so strongSwan
requests ESP-in-UDP even without `encap = yes`. Both encapsulation endpoint
ports must be at least 1024. Inner IPv4 and IPv6 traffic can share a tunnel;
the two outer endpoints must have the same address family.

Use nonzero `if_id_in` and `if_id_out` in the connection configuration.
`%unique` shares an interface between directions; `%unique-dir` uses separate
ones. Remove scripts that create or delete these interfaces. Overlay addresses
and routes remain the responsibility of the network configuration.

For `start_action = trap`, configure fixed nonzero interface IDs shared by the
trap and negotiated CHILD_SAs, for example `if_id_in = 42` and `if_id_out = 42`.
Assign different IDs to logical tunnels that need separate interfaces.
With strongSwan 6.1.0, a trap's `%unique` allocation is not passed to the
CHILD_SA it triggers, so their policies can bind to different interfaces.

Unsupported configuration includes transport/BEET mode, AH, IPComp, hardware
offload (including automatic offload), security labels, per-CPU SAs/acquires,
and SA/policy interface-name restrictions. Virtual address and host route/rule
installation are also unsupported.

Established-SA updates return `NOT_SUPPORTED`. In strongSwan's host-update
path, this requests a fresh CHILD_SA rekey instead of modifying the existing SA.
In-place MOBIKE migration is unsupported; the tests configure `mobike = no`.

### TFC, ICMP and usage

`tfc_padding` enables ESPv3 TFC padding in ordinary tunnel mode.
`icmp = yes` enables the requested SA/policy flags for forwarding ICMP errors,
including errors originating outside the negotiated traffic selectors.

On Linux 6.2 and later, SA usage queries return last-use times converted from
Unix time to strongSwan's monotonic clock. On earlier kernels, strongSwan uses
policy usage instead. Unused or unavailable timestamps are zero.

### IP-TFS

`mode = iptfs` requires Linux 6.14 or later with `xfrm_iptfs` support locally
and an IP-TFS-capable peer. It aggregates small inner packets and fragments
large inner packets across ESP packets. It does not generate constant-rate
cover traffic.
strongSwan may negotiate ordinary tunnel mode if the peer lacks IP-TFS support.
Keep `tfc_padding = 0` for IP-TFS; the daemon rejects combining the two.

The plugin reads these global `charon.iptfs` settings when opening its session:

| Setting | Default | Unit |
| --- | ---: | --- |
| `drop_time` | 1000000 | microseconds |
| `reorder_window` | 3 | packets |
| `init_delay` | 0 | microseconds |
| `max_queue_size` | 1048576 | bytes |
| `packet_size` | 0 | bytes; kernel-selected when zero |
| `dont_fragment` | false | boolean |

Restart strongSwan to apply changes. The peer's negotiated fragmentation
restriction is also honored. `charon.iptfs.accept_fragments` is handled by
strongSwan's IKE negotiation.

## Nix and NixOS

The flake provides `x86_64-linux` and `aarch64-linux` packages:

```sh
nix build                         # daemon and plugin
nix build .#charon-kernel-daemon    # daemon only
nix build .#kernel-rust-plugin     # plugin only
nix build .#strongswan             # matching strongSwan
nix build .#strongswan-headers     # matching headers and config.h
nix develop                       # toolchain and configured strongSwan headers
```

`flake.lock` pins the dependencies. The flake configures headers from the
matching strongSwan package, including its patches and configure flags.
The development shell sets `STRONGSWAN_SOURCE` and `CONFIG_H_DIR`.

Import this flake's `nixosModules.default`, then enable
`services.charon-kernel`. These are its options and defaults:

| Option | Default | Purpose |
| --- | --- | --- |
| `enable` | `false` | Enable the backend and `strongswan-swanctl`. |
| `package` | This flake's default package | Daemon, plugin and matching strongSwan. |
| `group` | `"ipsec"` | Static group for the kernel and VICI sockets. |
| `mtu` | `1400` | Tunnel MTU, 1280–65535. |
| `interfaceNamePrefix` | `"ranet"` | 1–7 ASCII letters, digits, underscores or hyphens. |
| `interfaceGroup` | `17227` | Reserved nonzero numeric Linux link group. |
| `masterDevice` | `"gravity"` | Existing master interface for tunnel links. |

The module requires its master device to exist before the first SA or trap policy is
installed. For example, create a VRF using systemd-networkd:

```nix
services.charon-kernel.enable = true;

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

The module installs the daemon/plugin and matching strongSwan into the system
profile and exposes `/lib/ipsec/plugins`. The strongSwan package searches
`/run/current-system/sw/lib/ipsec/plugins`, so plugins installed through
`environment.systemPackages` are discoverable. Its default VICI socket is
`/run/strongswan/charon.vici`, used by `swanctl` without a URI override.
The package disables EAP plugins.

The operator supplies strongSwan connection, plugin and firewall configuration.
For example, with `config` available in the NixOS module arguments:

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

Modular loading discovers the external plugin. Including the package's plugin
snippets retains its authentication, crypto, socket and VICI plugins.

Both services use dynamic users and the configured static socket group.
Charon has no capabilities; the daemon has only `CAP_NET_ADMIN`.
The module sets filesystem, device, IPC, process visibility, address-family,
syscall and executable-memory restrictions. See
[nix/module.nix](nix/module.nix) for the complete settings.

StrongSwan requires the daemon and starts after its readiness notification.
Systemd stop/restart jobs stop strongSwan before the daemon; stopping either
unit stops the pair. Both services use `Restart=always` with a two-second delay.
Unexpected process exits or RPC loss cause paired recovery with fresh
processes. Sudden daemon failure cannot preserve shutdown ordering.
Connection loading and initiation remain governed by the strongSwan
configuration.

## Cargo build and installation

The repository pins Rust 1.99.1 in `rust-toolchain.toml`. Building the plugin
also requires a native linker, libclang, cargo-c 0.10.26 or later, and two
absolute header paths:

- `STRONGSWAN_SOURCE`: the full source tree matching the installed strongSwan.
- `CONFIG_H_DIR`: a directory containing that build's generated `config.h`.
  It defaults to `STRONGSWAN_SOURCE`.

The source version, distribution patches and build configuration must match
the running strongSwan. Its installed development headers alone do not provide
the libcharon kernel interfaces. Compiled strongSwan artifacts are unnecessary
for building the plugin, but system headers required by the matching
`config.h` must be available.

Installing cargo-c from source also requires pkg-config and OpenSSL development
headers.

```sh
rustup toolchain install 1.99.1 --profile minimal --component rustfmt,clippy
cargo install cargo-c --version '0.10.26+cargo-0.100.0' --locked

export STRONGSWAN_SOURCE=/absolute/path/to/strongswan-source
export CONFIG_H_DIR=/absolute/path/to/config-directory

cargo cbuild -p strongswan-kernel-rust --release --locked --library-type=cdylib
cargo build -p charon-kernel-daemon --release --locked

cargo cinstall -p strongswan-kernel-rust --release --locked \
    --library-type=cdylib --prefix=/usr --libdir=lib
cargo install --locked --path . --root /usr
```

cargo-c installs `libstrongswan-kernel-rust.so` under
`<prefix>/<libdir>/ipsec/plugins`. Choose `--libdir` to match the host's plugin
directory. Use `--destdir` for staged plugin installation; stage the daemon
binary separately with the standard `install` utility.

The plugin is a Rust `cdylib`; `plugin/wrapper.h` is input to bindgen.
Charon provides its strongSwan symbols when loading the module.
Rebuild the plugin when changing the host strongSwan build.
Building only the daemon requires neither strongSwan headers nor libclang.

## Running outside NixOS

Run the daemon and strongSwan in the same network namespace. The daemon needs
`CAP_NET_ADMIN`. Charon can run as its final unprivileged user, with all
capability sets empty, writable runtime paths, and UDP ports at least 1024.

Give both services a shared static group, such as `ipsec`. The daemon's
`--group NAME|GID` option selects the socket group; its default is GID 0.
The socket is owned by the daemon and has mode 0660. Filesystem permissions,
including supplementary groups, authorize clients. Protect the parent directory
from replacement by untrusted users and allow the charon user to traverse it.

The daemon neither creates the parent directory nor unlinks an existing socket.
For systemd, the daemon's service settings can include:

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

This fragment supplies the daemon's runtime permissions. Also arrange paired
service dependencies, startup/shutdown ordering and restart behavior as in
[nix/module.nix](nix/module.nix). A failed kernel session requires restarting
both services.

Configure `kernel-rust` loading and disable `kernel-netlink`. Keep the normal
authentication, crypto, socket and VICI plugins loaded. Use high IKE/NAT-T
ports and `charon.install_routes = no`; the NixOS example shows the relevant
settings. The default kernel socket is
`/run/charon-kernel/charon-kernel.sock`. Change it with
`charon.plugins.kernel-rust.socket` and the daemon's `--socket` option.

Give charon its own writable runtime directory for VICI, such as
`/run/strongswan`, and configure credential access for its service user.
The plain `charon` executable also needs its compile-time PID-file directory
to be writable or isolated; `charon-systemd` does not use that PID file.

Charon binds its own UDP sockets and enables UDP encapsulation locally.
Do not configure `socket-default.fwmark` for capability-free charon: setting
`SO_MARK` requires a capability. SA output marks, including
`set_mark_out`, are configured by the daemon.

The standalone daemon defaults to MTU 1400, prefix `ranet`, link group 17227
and no master attachment. Its `--mtu`, `--ifname-prefix`,
`--interface-group` and `--master-device` options override those settings.
The master must already exist and remains managed by the network configuration.

## Interfaces and reconciliation

An interface named `ranet<if_id as eight hexadecimal digits>` is created before
the first SA or policy using that ID is installed. It is UP and multicast-enabled.
SAs and policy references, including traps and overlapping rekeys, share an
interface when their IDs match. The interface remains while any installed SA
or desired policy uses the ID. Removing the final owner releases the interface;
failed first installation rolls back temporary ownership.
IKE bypasses (`if_id = 0`) and larval SPI reservations do not retain interfaces.

A trap can therefore create an interface before any SA exists. Once the network
configuration supplies a route through it, matching traffic triggers ACQUIRE
delivery to charon and CHILD_SA negotiation. The interface remains available for
new traffic after the SAs are removed while the trap is still configured.

All interfaces in the configured numeric link group belong to the daemon,
regardless of native type or name. Group membership survives crashes and does
not require an iproute2 group-name entry. Names encode logical identity;
renaming an owned interface can cause replacement.

The daemon retains desired policies and the managed configuration of installed
SAs in memory. Normal ownership changes use targeted interface lookups,
creation and deletion. SA/policy notifications request repairs coalesced over
100 ms. Full interface discovery and repair run every five seconds, and during
session startup/shutdown; link notifications do not trigger full scans:

| Resource | Reconciliation |
| --- | --- |
| Global policies | Restore missing or changed desired policies; delete unwanted policies. Overlapping rekeys retain references and select the active template. |
| Owned interfaces | Restore missing links and managed MTU, master, UP, multicast and XFRM binding settings. Delete unwanted owned links. |
| Established SAs | Retire missing or changed SAs and notify strongSwan with hard expiry. Delete drifted/unwanted installed states; never reinstall old keys. |

Reconciliation and RPC mutations share a backend lock.
An external policy flush can recover without replacing SAs or interfaces.
SA loss instead requests fresh CHILD_SA negotiation. Policies can retain the
interface and its routes while no usable SA exists, so routing software must
detect peer reachability independently. Removing the final SA and policy owner
also removes the interface and its routes.

In-place interface repairs preserve unmanaged settings such as addresses,
aliases and queue lengths. Replacement loses these settings and routes.
The external network configuration must restore them when an interface is
recreated.

## Session lifecycle and cleanup

One Unix connection owns the daemon's single active charon session. Plugin
callbacks run synchronous RPCs on charon's calling threads. An eventfd wakes
charon's watcher when events are available; low-priority jobs fetch batches.
Idle operation sends no periodic RPCs or heartbeats. See
[PROTOCOL.md](PROTOCOL.md) for the transport and event mechanism.

A clean close requires strongSwan to remove its tunnel SAs and policies first.
It then removes bypass policies and flushes remaining SA/SPI state, permitting
a fresh session. Unexpected disconnect or event-queue overflow instead triggers
daemon cleanup and exit with an error. The plugin does not reconnect or replay
mutations; the service pair must restart and negotiate fresh SAs.

SIGTERM and SIGINT trigger explicit cleanup: global policies, the whole XFRM
state table, SPI reservations and owned interfaces are removed before exit.
Cleanup also runs without an open session. Errors are reported and produce a
nonzero exit. SIGKILL, aborts and crashes skip orderly cleanup; the next session
clears leftover kernel objects. Desired state and established sessions are
not recovered across daemon restarts.

Netlink uses neli's unmodified async router on the daemon's shared Tokio runtime.
It avoids neli's synchronous receive loop, which mishandles interrupted waits
after suspend/resume, SIGSTOP/SIGCONT and systemd freeze/thaw. Notification tasks
and shutdown cleanup use the same runtime, without a separate Netlink runtime.
Netlink requests have a five-second deadline. A timed-out request may already
have changed kernel state, so the socket is retired and the session fails;
mutations are not automatically replayed. Cleanup errors are reported, and
the next session retires leftover kernel objects.

The eventfd signals event availability. It does not signal daemon death;
the client detects transport failure when it next makes an RPC. The NixOS
module also manages process failure through systemd.

### IKE bypass limitation

`bypass_socket()` reads the borrowed IKE socket's family and local UDP port.
The daemon installs global bypass policies for outgoing UDP source ports and
incoming UDP destination ports. These exceptions apply to matching traffic
from any socket/process and last until session cleanup. They use `if_id = 0`;
tunnel policies use nonzero IDs.

IKE socket descriptors are not passed to the daemon, so socket-bound
`IP_XFRM_POLICY`/`IPV6_XFRM_POLICY` bypasses are unsupported.
The passed notification eventfd is separate from the IKE sockets.

### Network discovery

The daemon supplies read-only address/interface/subnet discovery and host
source-address/nexthop lookups. It caches link/address dumps until a link or
address event invalidates them. Route queries use the kernel FIB and routing
rules directly; routes through XFRM or excluded interfaces are rejected.

`charon.interfaces_use` and `charon.interfaces_ignore` are global lists of
exact interface names. A nonempty allowlist takes precedence. Address
enumeration excludes XFRM links, loopback/link-local addresses and
tentative, deprecated or failed-DAD addresses. Down and ignored interfaces
require explicit enumeration flags.

A caller-supplied or FIB-selected source may belong to another interface,
including an excluded one; a successful route lookup is authoritative.
Subnet nexthop queries and scoped IPv6 routing are unsupported.
Network-change notifications are coalesced at 100 ms intervals, separately
from XFRM expiry/acquire/mapping events.

## Tests

The Rust suite uses `rstest` for named cases and small parameter matrices.
Unit and RPC tests run without privileges. Daemon/kernel tests use the production
tarpc types directly and create a fresh network namespace per case. They cover
SA options and rejection/rollback, larval SPIs, expiry and loss notifications,
policy selectors and repair, unchanged periodic audits, interface ownership
including reused indices and crash leftovers, FIB lookups, address-cache
invalidation, event coalescing and cleanup with queued RPCs. A capability-free
client also exercises kernel operations through the socket. Cases can run in parallel.

The `unit-tests` flake check runs `cargo test` including the privileged cases
as root using `runInLinuxVM`. It needs neither strongSwan nor a NixOS system.

The separate NixOS test uses actual strongSwan with this backend on one machine and
upstream `kernel-netlink` on the other. It checks both initiation directions,
PSK and Ed25519 raw-public-key authentication, encrypted IPv4/IPv6 traffic,
AES-GCM, AES-CBC/HMAC, ESN, TFC and ICMP flags,
IP-TFS aggregation/fragmentation, trap-only interface creation and traffic-triggered
negotiation, rekeying, policy/interface repair, SA-loss
recovery, VICI loading/reloading of 200 unreachable-peer configurations under
route/link churn, socket access, service hardening and paired restart/shutdown behavior.
It also checks the plugin ABI against actual strongSwan libraries.

```sh
nix flake check -L
nix build .#checks.x86_64-linux.unit-tests -L
nix build .#checks.x86_64-linux.end-to-end -L
```

Both VM checks require KVM. The flake defines checks for both supported
architectures; the Python ABI fixture targets strongSwan 6.1.0 layouts.

For local unit/protocol tests, and Clippy with matching strongSwan header
paths set:

```sh
cargo test --locked -p charon-kernel-daemon -p kernel-rust-protocol
cargo clippy --locked --workspace --all-targets -- -D warnings
```

To also run the daemon/kernel cases locally, use root with iproute2 and
util-linux available. Each privileged test creates and restores its own network
namespace; no outer `unshare` or serial test execution is required:

```sh
cargo test --locked -p charon-kernel-daemon -p kernel-rust-protocol \
    -- --include-ignored --test-threads=4
```

Run an individual group or case by its Cargo test filter, for example:

```sh
cargo test --locked --test daemon policy_repair -- --ignored
```

The Python helpers under `tests/` are used only by the strongSwan NixOS test
for ABI calls, VICI operations, sandbox probes and forced RPC disconnects.

## Source layout

The plugin's C ABI adapters are in [plugin/src](plugin/src).
[protocol/src](protocol/src) contains the shared RPC types, client and eventfd
handoff. Policy, interface and immutable-SA controllers and their kernel traits
live in [src/policy.rs](src/policy.rs), [src/interfaces.rs](src/interfaces.rs)
and [src/sa.rs](src/sa.rs). Linux implementations are under
[src/linux](src/linux). [src/service](src/service) separates session lifecycle,
RPC dispatch, event delivery and reconciliation scheduling into modules.

The daemon and protocol crate forbid unsafe Rust. The plugin's unsafe code
implements strongSwan's C ABI and calls its host functions. SA keys cross the
private socket and remain in in-memory audit snapshots; queries do not return
them. Core dumps are disabled in the daemon. Serialization and Netlink buffers
are not guaranteed to be wiped.

## License and origin

GPL-2.0-or-later; see [COPYING](COPYING). The license text is strongSwan's
unchanged GPL v2 text. Linux XFRM and network semantics derive from its
kernel-netlink backend, credited in the source headers.
