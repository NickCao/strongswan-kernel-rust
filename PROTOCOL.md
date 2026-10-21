# tarpc kernel API

[protocol/src/lib.rs](protocol/src/lib.rs) defines the shared Rust types,
service trait and errors. `#[tarpc::service]` generates the client and dispatch.
Connections use Unix SOCK_STREAM sockets. Before starting tarpc, the daemon
sends a one-byte zero payload with one nonblocking eventfd through `SCM_RIGHTS`.
The plugin receives it with `MSG_CMSG_CLOEXEC`, then calls `open_session`.
Notifications start only after the session opens. Descriptor transfer uses
rustix's safe ancillary-message APIs and does not touch RPC framing.

RPC traffic uses tarpc's standard Serde transport: Bincode-encoded tarpc messages
in length-delimited frames, with an 8 MiB frame limit. Install matching plugin
and daemon builds; this internal binary API does not support mixing versions.
There is no custom message envelope or notification frame.

The plugin calls `Runtime::block_on()` directly on charon's calling threads,
using one shared Tokio current-thread runtime and one Unix connection. No plugin
thread is created. Tokio coordinates concurrent callers and drives its RPC
dispatch task while a call is active. Charon's existing watcher monitors the
passed eventfd. Its callback clears the counter with a nonblocking read and
queues a low-priority job, keeping the watcher registered. The job calls
`next_events`, delivers the batch after leaving the runtime, and returns
`JOB_REQUEUE_FAIR` while batches remain or another notification arrived during
the fetch. An empty reply with no pending wakeup stops the job. There is no
polling timer or additional client event queue.

Application errors distinguish invalid sessions, an occupied session and kernel
errors carrying a positive errno. tarpc handles request IDs, deadlines,
cancellation, framing and transport errors.

`open_session` binds the connection to the daemon's single active session and
returns feature flags. Its `interfaces_use` and `interfaces_ignore` arguments
carry charon's interface filters; a nonempty allowlist takes precedence over
the denylist. `next_events` uses that same connection and immediately returns
one queued batch of typed expiry, acquire, NAT mapping, or network change
notifications, or an empty batch when idle. No subscription token or second
connection is needed. The daemon queue is bounded; overflow invalidates the
connection instead of silently losing expiry events. The daemon keeps receiving
hard expiry events after a client disconnects to release expired SA interfaces.

The daemon writes to the eventfd when a batch becomes available, coalescing
wakeups until a batch is fetched. XFRM batches wake immediately. A pending roam
wakes at its existing 100 ms coalescing deadline, even if an intervening urgent
XFRM batch has already been delivered. Reading RPC replies cannot consume these
wakeups: the eventfd counter is independent of tarpc's socket and buffers.
Idle operation sends no periodic RPCs. The eventfd signals event availability
only; a disconnected daemon is detected by the next RPC call.

Higher-priority eligible jobs take precedence; fair requeue places further
batch fetches at the tail of their priority queue. Job cancellation wakes an
in-flight fetch without closing the shared connection. Unloading removes the
watcher and joins active event dispatch before closing the session. The watcher
callback only performs the nonblocking eventfd read and queues work; blocking
RPCs run in a job with cooperative cancellation. There is no pthread
cancellation through Rust RPC frames. Only the notification eventfd is passed;
RPC data contains no process-local pointers or descriptors.

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
