# Varlink kernel API

[io.ranet.Kernel.varlink](io.ranet.Kernel.varlink) defines the types, methods,
and errors. The Rust plugin and daemon share bindings generated from this IDL
with varlink_generator. The Varlink library handles standard JSON framing and
client protocol state, including streaming event replies.
The service supports org.varlink.service.GetInfo and
GetInterfaceDescription. For example:

```sh
varlinkctl introspect /run/charon-kernel/charon-kernel.sock io.ranet.Kernel
```

Connections are Unix SOCK_STREAM sockets. Each JSON message ends with NUL.
Requests on the control connection are serialized, as required by Varlink.
Replies may omit `parameters` for methods with no output. Standard Varlink errors describe
unknown methods and invalid parameter types; io.ranet.Kernel.KernelError
contains a positive Linux errno for rejected/kernel operations.

OpenSession authenticates ownership of the control connection and returns
feature flags plus a random token. Its interfacesUse and interfacesIgnore
arguments carry charon's interface filters; a nonempty allowlist takes
precedence over the denylist. WatchEvents requires a second connection
from the same UID/PID and that token, with `more: true`. Its first response
has `event.kind: ready`, then events use `continues: true`. Events are typed
expiry, acquire, NAT mapping, or network change notifications. The event
queue is bounded; a broken or stalled event channel invalidates control
instead of silently losing expiry events. The daemon keeps receiving hard
expiry events after a client disconnects to release expired SA interfaces.

SA keys are hexadecimal input strings. Algorithm identifiers use
strongSwan's encryption/integrity identifiers; optional kernel names support
registered algorithms. Mark values/masks, SPIs, interface IDs, and request
IDs are unsigned 32-bit values expressed as Varlink integers. Addresses are
numeric IPv4/IPv6 strings. Byte/packet counters and lifetime limits use
unsigned decimal strings to retain all uint64 values. Last-use timestamps
are monotonic seconds, matching the kernel interface. Negative or
out-of-range numbers and selectors that cannot be represented as XFRM
prefixes/port masks are rejected.

InstallSa always means tunnel-mode ESP with a nonzero interface ID. It
creates an up XFRM interface when necessary; no route, address, or explicit
interface-management methods exist. RemoveSa, FlushSas, or a hard expiry
release an unused interface. Policy reference counts preserve overlapping
rekey policies. FlushPolicies removes only session-owned tunnel policies,
retaining port bypasses. CloseSession succeeds only with no tunnel
SAs/policies and then removes bypasses and larval allocations.

BypassPort takes an address family (AF_INET/AF_INET6) and a UDP port at least
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
