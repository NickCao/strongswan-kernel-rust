// SPDX-License-Identifier: GPL-2.0-or-later
use futures::StreamExt;
use kernel_rust_protocol::{
    self as api,
    client::{CancellationToken, Client, Config},
    notification::Notification,
    *,
};
use rstest::rstest;
use std::{
    os::unix::net::{UnixListener, UnixStream},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::Duration,
};
use tarpc::{context::Context, server::Channel};

struct State {
    captured: Mutex<Vec<Captured>>,
    closes: AtomicUsize,
    query_barrier: Mutex<Option<Arc<tokio::sync::Barrier>>>,
    hold_events: AtomicBool,
    event_calls: AtomicUsize,
    events: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Vec<Event>>>,
}
#[derive(Debug, PartialEq, Eq)]
enum Captured {
    Sa(SaId, SaConfig),
    Policy(PolicyId, PolicyConfig),
}
#[derive(Clone)]
struct Fake(Arc<State>);
macro_rules! unsupported {
    ($($name:ident($($arg:ident: $ty:ty),*) -> $out:ty;)*) => {$ (
        async fn $name(self, _: Context, $($arg: $ty),*) -> api::Result<$out> {
            Err(api::Error::Kernel(libc::EOPNOTSUPP))
        }
    )*};
}
impl Kernel for Fake {
    async fn open_session(self, _: Context, config: SessionConfig) -> api::Result<SessionInfo> {
        assert_eq!(config.interfaces_use, "eth0");
        Ok(SessionInfo { features: 4 })
    }
    async fn close_session(self, _: Context) -> api::Result<()> {
        self.0.closes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    async fn next_events(self, _: Context) -> api::Result<Vec<Event>> {
        self.0.event_calls.fetch_add(1, Ordering::Relaxed);
        let mut events = self.0.events.lock().await;
        if self.0.hold_events.load(Ordering::Relaxed) {
            events.recv().await.ok_or(api::Error::InvalidSession)
        } else {
            Ok(events.try_recv().unwrap_or_default())
        }
    }
    async fn install_sa(self, _: Context, id: SaId, config: SaConfig) -> api::Result<()> {
        self.0
            .captured
            .lock()
            .unwrap()
            .push(Captured::Sa(id, config));
        Err(api::Error::Kernel(libc::EEXIST))
    }
    async fn install_policy(
        self,
        _: Context,
        id: PolicyId,
        config: PolicyConfig,
    ) -> api::Result<()> {
        self.0
            .captured
            .lock()
            .unwrap()
            .push(Captured::Policy(id, config));
        Err(api::Error::Kernel(libc::EOPNOTSUPP))
    }
    async fn query_sa(self, _: Context, _id: SaId, cpi: u16) -> api::Result<SaUsage> {
        assert_eq!(cpi, u16::MAX);
        let barrier = self.0.query_barrier.lock().unwrap().clone();
        if let Some(barrier) = barrier {
            barrier.wait().await;
        }
        Ok(SaUsage {
            bytes: u64::MAX,
            packets: u64::MAX - 1,
            last_use: 7,
        })
    }
    unsupported! {
        allocate_spi(_src: Endpoint, _dst: Endpoint, _protocol: u8, _minimum: u32, _maximum: u32) -> u32;
        allocate_cpi(_src: Endpoint, _dst: Endpoint) -> u16;
        update_sa(_id: SaId, _config: SaUpdate) -> ();
        remove_sa(_id: SaId, _cpi: u16) -> ();
        flush_sas() -> ();
        remove_policy(_id: PolicyId, _config: PolicyConfig) -> ();
        query_policy(_id: PolicyId) -> u64;
        flush_policies() -> ();
        bypass_port(_family: u16, _port: u16) -> ();
        get_source_address(_destination: Endpoint, _source: Option<Endpoint>) -> Endpoint;
        get_next_hop(_destination: Endpoint, _source: Option<Endpoint>, _prefix: Option<i32>) -> NextHop;
        get_interface(_address: Endpoint) -> String;
        list_addresses(_which: u32) -> Vec<Endpoint>;
        list_subnets() -> Vec<Subnet>;
    }
}
struct Fixture {
    _directory: tempfile::TempDir,
    config: Config,
    state: Arc<State>,
    events: tokio::sync::mpsc::Sender<Vec<Event>>,
    notifications: Arc<Notification>,
    sockets: mpsc::Receiver<UnixStream>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("kernel.sock");
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let (events, receiver) = tokio::sync::mpsc::channel(8);
        let notifications = Arc::new(Notification::new().unwrap());
        let notify = notifications.clone();
        let state = Arc::new(State {
            captured: Mutex::new(Vec::new()),
            closes: AtomicUsize::new(0),
            query_barrier: Mutex::new(None),
            hold_events: AtomicBool::new(false),
            event_calls: AtomicUsize::new(0),
            events: tokio::sync::Mutex::new(receiver),
        });
        let server = Fake(state.clone());
        let (accepted, sockets) = mpsc::channel();
        let (stop, shutdown) = tokio::sync::oneshot::channel();
        let worker = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::UnixListener::from_std(listener).unwrap();
                tokio::pin!(shutdown);
                loop {
                    tokio::select! {
                        _ = &mut shutdown => break,
                        connection = listener.accept() => {
                            let socket = connection.unwrap().0.into_std().unwrap();
                            notify.send(&socket).unwrap();
                            accepted.send(socket.try_clone().unwrap()).unwrap();
                            let stream = tokio::net::UnixStream::from_std(socket).unwrap();
                            let transport = transport::framed(stream);
                            let channel = tarpc::server::BaseChannel::with_defaults(transport);
                            let fake = server.clone();
                            tokio::spawn(async move {
                                channel.execute(fake.serve()).for_each(|response| async move { tokio::spawn(response); }).await;
                            });
                        }
                    }
                }
            });
        });
        Self {
            config: Config {
                path: path.to_str().unwrap().into(),
                session: SessionConfig {
                    interfaces_use: "eth0".into(),
                    interfaces_ignore: String::new(),
                    ..SessionConfig::default()
                },
            },
            _directory: directory,
            state,
            events,
            notifications,
            sockets,
            stop: Some(stop),
            worker: Some(worker),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.worker.take().unwrap().join().unwrap();
    }
}
fn endpoint() -> Endpoint {
    Endpoint {
        address: "fe80::1".parse().unwrap(),
        port: u16::MAX,
        flow_info: 0x12345678,
        scope_id: u32::MAX,
    }
}
fn sa_id() -> SaId {
    SaId {
        src: endpoint(),
        dst: endpoint(),
        spi: u32::MAX,
        protocol: 51,
        interface_id: 0,
        mark: Mark {
            value: u32::MAX,
            mask: u32::MAX,
        },
    }
}
fn selector() -> Selector {
    Selector {
        kind: u32::MAX,
        dynamic: true,
        from: "::".parse().unwrap(),
        to: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap(),
        protocol: u8::MAX,
        from_port: 0,
        to_port: u16::MAX,
    }
}
fn sa_config(selectors: bool, optional: bool) -> SaConfig {
    let limit = || LifetimeLimit {
        life: u64::MAX,
        rekey: u64::MAX - 1,
        jitter: u64::MAX - 2,
    };
    SaConfig {
        reqid: u32::MAX,
        acquire_sequence: u32::MAX,
        mode: u32::MAX,
        src_selectors: selectors.then(|| vec![selector()]),
        dst_selectors: selectors.then(Vec::new),
        interface: optional.then(String::new),
        encryption: Algorithm {
            id: u16::MAX,
            name: "future-cipher".into(),
            key: vec![0, 128, 255],
        },
        integrity: Algorithm {
            id: u16::MAX - 1,
            name: "future-auth".into(),
            key: vec![255, 0, 254],
        },
        lifetime: optional.then(|| Lifetime {
            time: limit(),
            bytes: limit(),
            packets: limit(),
        }),
        replay_window: u32::MAX,
        ipcomp: u16::MAX,
        cpi: u16::MAX,
        cpu: u32::MAX - 1,
        hw_offload: u32::MAX,
        security_label: optional.then(|| vec![0, 255, 128]),
        esn: true,
        udp_encapsulation: true,
        output_mark: Mark {
            value: u32::MAX,
            mask: u32::MAX,
        },
        tfc: u32::MAX,
        copy_df: false,
        copy_ecn: true,
        copy_dscp: u32::MAX,
        iptfs_dont_fragment: true,
        forward_icmp: true,
        initiator: true,
        inbound: true,
        update: true,
    }
}
fn policy_id() -> PolicyId {
    PolicyId {
        direction: u32::MAX,
        src: selector(),
        dst: selector(),
        mark: Mark {
            value: 42,
            mask: 255,
        },
        interface_id: u32::MAX,
        interface: Some("eth0".into()),
        security_label: Some(vec![255, 0, 128]),
    }
}
fn policy_config() -> PolicyConfig {
    PolicyConfig {
        kind: u32::MAX,
        priority: u32::MAX,
        manual_priority: u32::MAX,
        hw_offload: u32::MAX,
        pcpu_acquires: true,
        forward_icmp: true,
        src: Some(endpoint()),
        dst: Some(endpoint()),
        sa: Some(PolicySa {
            mode: u32::MAX,
            reqid: u32::MAX,
            policy_count: u32::MAX,
            esp: ProtocolSa {
                used: false,
                spi: u32::MAX,
            },
            ah: ProtocolSa {
                used: true,
                spi: u32::MAX - 1,
            },
            ipcomp: CompressionSa {
                transform: u16::MAX,
                cpi: u16::MAX,
            },
        }),
    }
}
#[rstest]
fn complete_native_inputs_and_unsigned_outputs_over_tarpc_uds(
    #[values(false, true)] selectors: bool,
    #[values(false, true)] optional: bool,
) {
    let fixture = Fixture::new();
    let client = Client::connect(&fixture.config).unwrap();
    assert_eq!(client.features(), 4);
    let error = client
        .request(client.rpc().install_sa(
            api::context::current(),
            sa_id(),
            sa_config(selectors, optional),
        ))
        .unwrap_err();
    assert_eq!(error.errno, Some(libc::EEXIST));
    assert_eq!(
        fixture.state.captured.lock().unwrap()[0],
        Captured::Sa(sa_id(), sa_config(selectors, optional))
    );
    client
        .request(
            client
                .rpc()
                .install_policy(api::context::current(), policy_id(), policy_config()),
        )
        .unwrap_err();
    assert_eq!(
        fixture.state.captured.lock().unwrap()[1],
        Captured::Policy(policy_id(), policy_config())
    );
    let usage = client
        .request(
            client
                .rpc()
                .query_sa(api::context::current(), sa_id(), u16::MAX),
        )
        .unwrap();
    assert_eq!(
        (usage.bytes, usage.packets, usage.last_use),
        (u64::MAX, u64::MAX - 1, 7)
    );
    client.close().unwrap();
    client.close().unwrap();
    assert_eq!(fixture.state.closes.load(Ordering::Relaxed), 1);
}
#[rstest]
#[case::single_event(1)]
#[case::large_batch(300)]
fn empty_and_large_batches_share_one_connection_and_disconnect_disables_control(
    #[case] count: usize,
) {
    let fixture = Fixture::new();
    let client = Client::connect(&fixture.config).unwrap();
    let stop = CancellationToken::new();
    assert!(client.next_events(&stop).unwrap().unwrap().is_empty());
    let event = Event {
        kind: EventKind::Expire,
        expiry: Some(Expiry {
            protocol: 50,
            spi: u32::MAX,
            destination: endpoint(),
            hard: true,
        }),
        acquire: None,
        mapping: None,
        address_changed: None,
    };
    fixture
        .events
        .blocking_send(vec![event.clone(); count])
        .unwrap();
    let batch = client.next_events(&stop).unwrap().unwrap();
    assert_eq!(batch.len(), count);
    for received in batch {
        assert_eq!(
            received.expiry.unwrap().destination,
            event.expiry.as_ref().unwrap().destination
        );
    }
    assert!(client.next_events(&stop).unwrap().unwrap().is_empty());
    let socket = fixture
        .sockets
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    assert!(
        fixture.sockets.try_recv().is_err(),
        "only one UDS connection"
    );
    socket.shutdown(std::net::Shutdown::Both).unwrap();
    assert!(client.next_events(&stop).is_err());
    assert!(client
        .request(
            client
                .rpc()
                .query_sa(api::context::current(), sa_id(), u16::MAX)
        )
        .is_err());
}
#[test]
fn different_calling_threads_share_the_current_thread_runtime() {
    let fixture = Fixture::new();
    // A reply requires all eight callers to have an RPC in flight. This
    // catches accidental serialization without depending on thread timing.
    *fixture.state.query_barrier.lock().unwrap() = Some(Arc::new(tokio::sync::Barrier::new(8)));
    let client = Client::connect(&fixture.config).unwrap();
    thread::scope(|scope| {
        for _ in 0..8 {
            let client = client.clone();
            scope.spawn(move || {
                for _ in 0..25 {
                    let usage = client
                        .request(
                            client
                                .rpc()
                                .query_sa(api::context::current(), sa_id(), u16::MAX),
                        )
                        .unwrap();
                    assert_eq!(usage.bytes, u64::MAX);
                }
            });
        }
    });
    client.close().unwrap();
}
#[test]
fn eventfd_wakes_an_idle_client_without_periodic_event_rpcs() {
    let fixture = Fixture::new();
    let client = Client::connect(&fixture.config).unwrap();
    thread::sleep(Duration::from_millis(50));
    assert_eq!(fixture.state.event_calls.load(Ordering::Relaxed), 0);
    fixture
        .events
        .blocking_send(vec![Event {
            kind: EventKind::Roam,
            expiry: None,
            acquire: None,
            mapping: None,
            address_changed: Some(true),
        }])
        .unwrap();
    fixture.notifications.notify().unwrap();
    // A control RPC must not consume the notification, even if it reads ahead.
    client
        .request(
            client
                .rpc()
                .query_sa(api::context::current(), sa_id(), u16::MAX),
        )
        .unwrap();
    // With no client runtime running, only the eventfd becomes readable.
    use rustix::event::{poll, PollFd, PollFlags, Timespec};
    let mut ready = [PollFd::new(client.notification(), PollFlags::IN)];
    assert_eq!(
        poll(
            &mut ready,
            Some(&Timespec {
                tv_sec: 2,
                tv_nsec: 0
            })
        )
        .unwrap(),
        1
    );
    let mut socket_ready = [PollFd::new(client.socket(), PollFlags::IN)];
    assert_eq!(
        poll(&mut socket_ready, Some(&Timespec::default())).unwrap(),
        0
    );
    assert!(client.notification().drain().unwrap());
    let batch = client
        .next_events(&CancellationToken::new())
        .unwrap()
        .unwrap();
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].address_changed, Some(true));
    thread::sleep(Duration::from_millis(50));
    assert_eq!(fixture.state.event_calls.load(Ordering::Relaxed), 1);
    client.close().unwrap();
}
#[test]
fn canceling_an_event_poll_does_not_block_or_cancel_control_calls() {
    let fixture = Fixture::new();
    fixture.state.hold_events.store(true, Ordering::Relaxed);
    let client = Client::connect(&fixture.config).unwrap();
    let stop = CancellationToken::new();
    thread::scope(|scope| {
        let events = scope.spawn(|| client.next_events(&stop).unwrap());
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while fixture.state.event_calls.load(Ordering::Relaxed) == 0 {
            assert!(std::time::Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        let usage = client
            .request(
                client
                    .rpc()
                    .query_sa(api::context::current(), sa_id(), u16::MAX),
            )
            .unwrap();
        assert_eq!(usage.bytes, u64::MAX);
        stop.cancel();
        assert!(events.join().unwrap().is_none());
    });
    client.close().unwrap();
    assert_eq!(fixture.state.closes.load(Ordering::Relaxed), 1);
}
