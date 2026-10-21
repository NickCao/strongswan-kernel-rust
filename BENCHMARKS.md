# Event delivery comparison

The eventfd implementation (`2834370`) was sampled on 2026-10-21 with matching
release daemon/plugin pairs in the same two-vCPU NixOS VM. The table uses one
completed trial per implementation, as the user requested rough results.
Each callback trial contains 5,000 calls; notification medians contain ten
route probes. These are rough samples, not a completed repeated benchmark.

| Measurement | Tokio worker (`adbea09`) | Busy polling (`94da3b5`) | Socket notifications (`560f002`) | Eventfd (`2834370`) |
| --- | ---: | ---: | ---: | ---: |
| Callback p50 | 211.2 us | 147.4 us | 111.4 us | 155.4 us |
| Callback p95 | 352.1 us | 249.0 us | 193.3 us | 264.5 us |
| Client CPU / 5,000 callbacks | 0.587 s | 0.460 s | 0.363 s | 0.317 s |
| Daemon CPU during callback loop | 0.600 s | 0.500 s | 0.460 s | 0.530 s |
| Combined idle CPU, core equivalents | 0.0000 | 1.1687 | 0.0033 | 0.0033 |
| Idle roam notification p50 | 51.7 ms | 49.8 ms | 9.3 ms | 10.2 ms |
| VICI: initial / reload, quiet | 1.945 / 0.907 s | 2.386 / 1.021 s | 2.153 / 0.774 s | 2.759 / 0.237 s |
| VICI: initial / reload, route churn | 1.806 / 1.069 s | 2.396 / 0.993 s | 2.090 / 0.895 s | 2.097 / 0.909 s |

Eventfd retains the low idle CPU and prompt notifications of socket
notifications. Its callback and quiet initial-load latency were higher in this
sample, while VICI under churn was similar. The quiet reload was faster. These
single-run results do not establish a consistent latency improvement or regression.
Zero idle CPU means no observed process ticks in the three-second sample;
0.0033 cores is about 0.33% of one CPU and busy polling consumed about 117%.

The new harness restarts services between quiet/churn workloads and stops them
before the standalone ABI fixture, so a second busy client does not compete
with the measured callback client. Its route worker uses a persistent
line-buffered `ip -batch` process, with a link-query acknowledgement after each
ten-route batch and a 10 ms pause. This avoids the process-creation stalls found
in the previous worker. Every completed churn phase made progress, but actual
counts still differed: initial/reload counts were 1610/760 for the Tokio worker,
2130/890 for busy polling, 190/780 for socket notifications and 90/790 for eventfd.
Churn comparisons are descriptive, not measurements at an identical update rate.
The remaining callback/notification methodology is described below.

Raw samples, scripts, exact package paths and logs are preserved in
`/root/charon-kernel-eventfd-benchmark/`. The eventfd release package is
`/nix/store/v12lg3zhhjpaxavkdxlgsgyac8nga2cf-strongswan-kernel-rust-0.1.0`.
The full mixed-peer x86_64 NixOS test passed in 303.29 seconds, with the Rust
backend on one peer and upstream `kernel-netlink` on the other, including traffic
in both directions, both cipher cases, recovery, hardening and shutdown.
Its log is `/root/charon-kernel-mixed-peer-final-nix.log`.

## Earlier full comparison

The following measurements describe the previous `560f002` socket-notification
implementation and use the older benchmark harness.

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
