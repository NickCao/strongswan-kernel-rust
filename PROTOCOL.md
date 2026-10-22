# Kernel RPC and backend contract

[protocol/src/lib.rs](protocol/src/lib.rs) defines the Rust service, messages
and application errors. `#[tarpc::service]` generates the client and server
dispatch. Install matching daemon and plugin builds; the binary protocol has
no version negotiation or cross-version compatibility guarantee.

## Connection setup

Both processes use a Unix `SOCK_STREAM` connection. Filesystem permissions on
the protected socket path authorize the client.

Before starting tarpc, the daemon sends a zero byte with one nonblocking
eventfd using `SCM_RIGHTS`. The client receives the descriptor with
`MSG_CMSG_CLOEXEC`. The transfer uses rustix ancillary-message APIs.
Subsequent traffic uses tarpc's standard Serde/Bincode transport with
length-delimited frames and an 8 MiB frame limit.

`open_session(SessionConfig)` claims the daemon's single active session and
returns the IPsec feature bitmask. Its configuration contains:

- `interfaces_use` and `interfaces_ignore`: comma-separated exact interface
  names. A nonempty allowlist takes precedence over the denylist.
- `iptfs`: the global IP-TFS settings listed in
  [README.md](README.md#ip-tfs).

The plugin reads these global settings at load time. Source-selection RPCs
carry the destination and optional source address.
See [plugin/src/host.rs](plugin/src/host.rs) for the strongSwan setting names.

Calls require an open, connected session on their own connection. A second
session is rejected as busy. Application failures retain kernel errno values,
access/session errors or a `Failed(message)` for failures without an OS errno.
The client preserves application and tarpc transport errors. Plugin logs include
the operation and error chain; errno values determine strongSwan status codes.
tarpc handles request IDs, deadlines and cancellation.

## Event delivery and runtime

`Event` carries its payload in one of four variants: `Expire(Expiry)`,
`Acquire(Acquire)`, `Mapping(Mapping)` or `Roam { address_changed: bool }`.

The plugin shares one Tokio current-thread runtime. Synchronous C callbacks
call `Runtime::block_on()` on charon's calling threads. Concurrent callers
share its scheduler without serializing whole RPCs under a mutex.
The plugin creates no threads.

The daemon handles each accepted connection on a thread with its own
current-thread Tokio runtime. An open session starts route and XFRM notification
workers and a reconciliation worker. Backend operations are serialized by
the session's backend mutex.

The daemon queues typed expiry, acquire and NAT mapping events in a bounded
queue of 256 batches. Network changes are accumulated separately and coalesced
at 100 ms intervals, retaining whether addresses changed. The eventfd wakes
the plugin when a batch is available or a pending network-change notification
becomes due. Wakeups coalesce until a batch is fetched.

Charon's watcher clears the eventfd counter and queues a low-priority
processor job. The watcher remains registered. The job calls `next_events()`,
which immediately returns one queued batch plus any due network-change event,
or an empty result when idle. Dispatch into strongSwan happens after leaving
the runtime.
The job fairly requeues while batches or racing wakeups remain, and stops after
an empty result with no pending wakeup. There is no polling timer or heartbeat.

An eventfd wakeup carries no RPC data, and socket reads cannot consume it.
Only the eventfd is passed; IKE socket descriptors are not transferred.
The eventfd does not signal a disconnected daemon. Transport failure is
detected on the next RPC.

Unloading cancels event fetching, removes the watcher and waits for active
event dispatch before closing the session. RPC cancellation is cooperative;
Rust RPC frames are not subject to pthread cancellation.

## Operations and data

| RPCs | Behavior |
| --- | --- |
| `allocate_spi` | Reserve an ESP SPI from the requested range. Reservations do not retain an interface. |
| `install_sa` | Install tunnel/IP-TFS ESP with a nonzero interface ID. Prepare the interface first and release it if installation fails. |
| `update_sa` | Return unsupported. strongSwan's host-update path may request a fresh CHILD_SA rekey. |
| `query_sa` / `query_policy` | Return usage from a direct kernel lookup. |
| `remove_sa` / `flush_sas` | Release desired SAs and unused interfaces. Flush also clears the entire XFRM state table and SPI reservations. |
| `install_policy` / `remove_policy` | Maintain strongSwan policy references and the selected effective policy. |
| `flush_policies` | Clear tunnel-policy references and reconcile, retaining desired IKE bypasses. |
| `bypass_port` | Install global UDP port bypasses for IPv4/IPv6, requiring a port of at least 1024. |
| `get_source_address` / `get_next_hop` | Read the host route from the kernel FIB. Subnet nexthop queries are unsupported. |
| `get_interface` / `list_addresses` / `list_subnets` | Read usable underlay interfaces, addresses and subnets. |
| `allocate_cpi` | Return unsupported. |

There are no RPCs to create addresses, routes or interfaces independently.
The plugin's virtual-address and route mutation callbacks return
`NOT_SUPPORTED` locally. SA and policy configuration fields are forwarded
before capability checks in the daemon; carrying a field does not imply that
the Linux backend implements it. See
[the supported configuration](README.md#supported-configuration).

Shared types retain:

- Endpoint IP address, port, IPv6 flow information and scope ID.
- Native unsigned SPIs, interface/request IDs and mark values/masks.
- Full `u64` lifetime limits, jitter and usage counters.
- Algorithm transform IDs, optional registered kernel names and byte-vector keys.
- SA modes, selectors, flags, direction, compression, offload, CPU, interface
  and security-label inputs; policy ESP/AH/IPComp configuration.

strongSwan enum fields use shared Rust enums with numeric Serde encoding;
unknown values retain their original numbers. Address and feature bitmasks
use `bitflags` and retain unknown bits across RPC.

Query last-use values are monotonic seconds, or zero when unused/unavailable.
The Linux adapter converts native timestamps. strongSwan already applies
lifetime jitter. Its tunnel traffic selectors become policies rather than
selectors on each SA. Native SA lookup keys exclude UDP ports and IPv6
sockaddr metadata; transporting that metadata does not add scoped IPv6 routing.

Port bypasses match outgoing UDP source ports and incoming UDP destination
ports. They are global policies whose lifetime follows the session, rather
than socket-bound policies. See the
[IKE bypass limitation](README.md#ike-bypass-limitation).

## Desired state and kernel traits

The session's backend lock covers observation, reconciliation and mutations.
Notifications schedule a pass after up to 100 ms of coalescing; a five-second
audit also runs. Scheduling and lock contention can delay actual execution.

- `PolicyKernel` provides list/get/create/update/delete. The controller
  canonicalizes selectors and marks, retains strongSwan references, resolves
  priorities and compares effective configuration. The Linux backend inventories
  all global policies, including unsupported native configurations. Its opaque
  handles contain the policy index and native lookup qualifiers.
- `InterfaceKernel` provides list/create/update/delete. Desired interfaces
  derive from installed SA ownership. Observations expose managed settings;
  handles expose logical identity. Linux discovers ownership through the numeric
  link group and identity through the encoded name, without an identity cache.
  Mutations target the interface index.
- `SaKernel` provides allocation, list/get/create/delete and bulk flush.
  The controller retains canonical installed configuration and installation
  time. Audits exclude counters, usage and live replay/sequence state.
  Missing or changed established SAs are retired and reported through hard expiry;
  old keys are never reinstalled. Snapshots include keys and remain in memory.

Policy and interface updates may repair an object in place or replace it;
that choice belongs to the backend. Unwanted, duplicate and unidentified
owned objects are removed. Interface replacement loses unmanaged settings;
external network configuration must restore them.

`install_sa` with `update = true` only completes a recorded larval
reservation. If it has expired, first installation may use add instead.
This operation cannot update an established SA.
Acquisition placeholders remain subject to their normal kernel timeout;
startup, flush and shutdown clear them too.

## Close, failure and shutdown

`close_session` requires no remaining desired tunnel SAs or policies.
It flushes SA/SPI state and removes bypasses/global policies.
A clean close permits a new session on a new connection.
Connections that never open a session do not cause daemon shutdown.

Unexpected loss of an opened session, failure of an active Netlink notification
worker or event-queue overflow wakes the daemon's main loop. It stops accepting
clients, disables mutations and repairs, cleans the global policy/state tables
and owned interfaces, and exits with an error.
SIGTERM and SIGINT use signalfd to request the same cleanup in normal Rust
execution context; successful signal-driven cleanup exits normally.

A failed exchange can leave a mutation applied without its reply.
The client neither replays nor reconnects. Recovery requires restarting the
service pair and negotiating fresh SAs. Startup cleanup discovers leftovers;
it does not restore the previous desired state or IKE session.
