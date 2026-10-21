# Event delivery comparison

Measured on 2026-10-21 with matching release daemon/plugin pairs and unmodified
strongSwan 6.1.0 in one NixOS VM: two vCPUs, 768 MiB RAM, Linux 6.18.56 and
`kvm-clock`. Fifteen alternating trials give five runs per implementation.

| Measurement | Tokio worker (`adbea09`) | Current-thread polling (`94da3b5`) | Event-driven (`560f002`) |
| --- | ---: | ---: | ---: |
| Callback p50 | 216.3 us | 107.7 us | 115.0 us |
| Callback p95 | 328.2 us | 292.9 us | 221.4 us |
| Callback p99 | 406.4 us | 450.9 us | 297.8 us |
| Client CPU / 5,000 callbacks | 0.565 s | 0.296 s | 0.359 s |
| Daemon CPU during callback loop | 0.560 s | 0.250 s | 0.460 s |
| Combined idle CPU, core equivalents | 0.0033 | 1.1784 | 0.0033 |
| Idle roam notification p50 | 51.9 ms | 49.8 ms | 10.1 ms |
| Idle roam notification p95 | 53.9 ms | 105.6 ms | 20.6 ms |
| Maximum measured roam latency | 103.0 ms | 120.7 ms | 42.3 ms |
| VICI: initial 200 connections, quiet | 2.021 s | 2.320 s | 2.079 s |
| VICI: reload/reuse, quiet | 0.761 s | 0.947 s | 0.878 s |
| VICI: initial 200 connections, route churn | 2.014 s | 2.392 s | 2.021 s |
| VICI: reload/reuse, route churn | 0.910 s | 0.980 s | 0.772 s |

The event-driven version cuts idle CPU by about 99.7% relative to continuous
polling, returning to the old client's idle level. A core equivalent is CPU
seconds / elapsed wall time; 1.1784 cores is about 118% CPU in `top`, while
0.0033 cores is about 0.33%. These are three-second idle samples with a 10 ms
CPU tick resolution, rather than a guarantee of zero idle work.

Median callback latency is about 47% lower than the old Tokio-worker client.
Compared with continuous polling, median latency is about 7% higher and the
callback loop uses more CPU, while tail latency improves. Initial VICI timing
is close to the old baseline. Quiet reload timing was higher than the old
client's, so these results do not show an improvement for every VICI operation.

## Method and limits

Callback measurements traverse the real strongSwan C ABI, UDS RPC, daemon and
kernel FIB lookup in an isolated network namespace. Each run uses a cap-free
client with four active host workers, 100 warmup calls and 5,000 measured calls.
Latency excludes result destruction. Client CPU includes all process threads,
the Python loop and destruction; daemon CPU includes concurrent event fetches.
Reported values are medians of each run's measurements or quantiles.

VICI follows a ranet-like load/list/asynchronous-initiate sequence for 200
unreachable peers, followed by reload/reuse. It does not execute ranet or
establish 200 CHILD SAs. Both modes seed 10,000 routes before measurement.
Quiet mode has no background route churn. Churn mode replaces ten routes per
`ip -batch` call, pauses 5 ms and alternates gateways every 100 updates. Actual
completed route-update counts vary substantially, including phases with zero
completed batches. They are retained in the raw results. Churn timings are
descriptive and must not be read as a controlled comparison at an identical
BGP update rate.

Notification quantiles pool 50 route probes per implementation. Probes are
150 ms apart and measure from a child's route-update request to a real
strongSwan roam-listener callback, including pipe and `ip` invocation costs.
The event-driven adapter can send immediately when the existing roam deadline
has passed; continuous route activity remains coalesced over 100 ms between
deliveries. These are idle roam measurements, not hard-SA-expiry measurements
or latency guarantees under higher-priority saturation. The ABI fixture uses
a fresh real kernel interface with an observation listener; full IKE/CHILD
handling is covered by the NixOS test.

## Validation and artifacts

The implementation passed 33 regular tests, three privileged tests run
serially in an isolated namespace, six native kernel integration scenario
groups, eight clean capability-free ABI sessions without added plugin threads
or resource leaks, and Clippy with warnings denied. The complete two-VM
x86_64 NixOS end-to-end test passed in 305.13 seconds, covering AES-GCM and
AES-CBC/HMAC IPv4/IPv6 traffic, rekey, SA loss, interface/policy recovery,
DynamicUser hardening, service dependencies and shutdown cleanup. aarch64
outputs were evaluated but not executed.

This VM's reproducible harness, package paths, full trial results, aggregates,
validation records and logs are preserved in
`/root/charon-kernel-event-driven-benchmark/`. See its `README.md`, `compare.py`,
`results.json`, `summary.json` and `validation.json`. Validation logs are
`/root/charon-kernel-event-driven-{unit,native,integration,abi,clippy,nix}.log`.
The measured event-driven package is
`/nix/store/54zls8vhjl66ykvg5mcm4xy3qdzzl6c8-strongswan-kernel-rust-0.1.0`.
