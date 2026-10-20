# tarpc kernel API

[protocol/src/lib.rs](protocol/src/lib.rs) defines the shared Rust types,
service trait and errors. `#[tarpc::service]` generates the client and dispatch.
Connections are Unix SOCK_STREAM sockets carrying Bincode-encoded tarpc messages
in length-delimited frames, with an 8 MiB frame limit. Install matching plugin
and daemon builds; this internal binary API does not support mixing versions.

The plugin bridges strongSwan's synchronous callbacks using `Runtime::block_on()`
on charon's calling threads. One shared Tokio worker drives socket I/O and
receives events into a bounded queue, waking charon's watcher, which invokes
strongSwan callbacks on its own workers.
Application errors distinguish invalid sessions, an occupied session and kernel
errors carrying a positive errno. tarpc handles request IDs, deadlines,
cancellation, framing and transport errors.

`open_session` authenticates ownership of the control connection and returns
feature flags plus a random token. Its `interfaces_use` and `interfaces_ignore`
arguments carry charon's interface filters; a nonempty allowlist takes
precedence over the denylist. `subscribe_events` requires a second connection
from the same UID/PID and that token. After successful subscription,
`next_events` waits for a batch of typed expiry, acquire, NAT mapping, or
network change notifications. Quiet
subscriptions return an empty heartbeat after 30 seconds; the plugin uses a
60-second event deadline. The event queue is bounded; a broken or stalled event channel invalidates control
instead of silently losing expiry events. The daemon keeps receiving hard
expiry events after a client disconnects to release expired SA interfaces.

SA keys and security labels use byte vectors. Algorithm identifiers use
strongSwan's encryption/integrity identifiers; optional kernel names support
registered algorithms. Mark values/masks, SPIs, interface IDs, and request
IDs use native `u32` values. Endpoints retain `IpAddr`, port, IPv6 flow information
and scope ID. Counters and all lifetime limits/jitter use `u64`. Last-use
timestamps are monotonic seconds, matching the kernel interface. SA and policy
inputs carry the complete strongSwan callback data, including unsupported
options; the daemon's adapter rejects unsupported configurations before calling
the existing backend. Its supported kernel model remains tunnel-mode ESP over
XFRM interfaces. Discovery's backend currently uses IP and port; transporting
IPv6 metadata does not add scoped routing support.

`install_sa` currently requires tunnel-mode ESP with a nonzero interface ID. It
creates an up XFRM interface when necessary; no route, address, or explicit
interface-management methods exist. `remove_sa`, `flush_sas`, or a hard expiry
release an unused interface. Policy reference counts preserve overlapping
rekey policies. `flush_policies` clears desired tunnel policies and reconciles,
retaining port bypasses. `close_session` succeeds only with no tunnel
SAs/policies and then removes bypasses and larval allocations.

`bypass_port` takes an address family (AF_INET/AF_INET6) and a UDP port at least
1024. Charon binds and enables UDP encapsulation itself; no descriptors are
passed. Read-only network discovery caches link/address Netlink dumps and
invalidates them on link/address changes. Source-address and nexthop queries
use host-only kernel FIB lookups, including policy routing. XFRM links are
excluded from address/subnet enumeration, address-to-interface queries, and
underlay route selection. Discovery honors interfaces_use/interfaces_ignore
and does not install host routes, routing rules, or virtual IPs. Network
change notifications are coalesced at 100 ms intervals; XFRM events are
delivered separately without that delay.

A failed transport exchange leaves mutation results uncertain. The client
does not replay or reconnect automatically. Unexpected disconnects preserve
kernel objects and reject replacement sessions until a coordinated daemon
restart. The protocol has no restart recovery or persistent ownership journal.
