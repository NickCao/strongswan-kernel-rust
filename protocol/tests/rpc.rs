// SPDX-License-Identifier: GPL-2.0-or-later
use futures::StreamExt;
use kernel_rust_protocol::{
    self as api,
    client::{Client, Config},
    *,
};
use serde_json::{json, Value};
use std::{
    io,
    os::unix::net::{UnixListener, UnixStream},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::Duration,
};
use tarpc::{context::Context, server::Channel};

struct State {
    captured: Mutex<Vec<Value>>,
    closes: AtomicUsize,
    reject_watch: bool,
    events: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Vec<Event>>>,
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
        Ok(SessionInfo {
            token: [42; 32],
            features: 4,
        })
    }
    async fn close_session(self, _: Context) -> api::Result<()> {
        self.0.closes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    async fn subscribe_events(self, _: Context, token: SessionToken) -> api::Result<()> {
        assert_eq!(token, [42; 32]);
        if self.0.reject_watch {
            Err(api::Error::InvalidSession)
        } else {
            Ok(())
        }
    }
    async fn next_events(self, _: Context) -> api::Result<Vec<Event>> {
        self.0
            .events
            .lock()
            .await
            .recv()
            .await
            .ok_or(api::Error::InvalidSession)
    }
    async fn install_sa(self, _: Context, id: SaId, config: SaConfig) -> api::Result<()> {
        self.0
            .captured
            .lock()
            .unwrap()
            .push(json!({"id":id,"config":config}));
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
            .push(json!({"id":id,"config":config}));
        Err(api::Error::Kernel(libc::EOPNOTSUPP))
    }
    async fn query_sa(self, _: Context, _id: SaId, cpi: u16) -> api::Result<SaUsage> {
        assert_eq!(cpi, u16::MAX);
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
        list_addresses(_which: i32) -> Vec<Endpoint>;
        list_subnets() -> Vec<Subnet>;
    }
}
struct Fixture {
    _directory: tempfile::TempDir,
    config: Config,
    state: Arc<State>,
    events: tokio::sync::mpsc::Sender<Vec<Event>>,
    sockets: mpsc::Receiver<UnixStream>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Fixture {
    fn new(reject_watch: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("kernel.sock");
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let (events, receiver) = tokio::sync::mpsc::channel(8);
        let state = Arc::new(State {
            captured: Mutex::new(Vec::new()),
            closes: AtomicUsize::new(0),
            reject_watch,
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
                            accepted.send(socket.try_clone().unwrap()).unwrap();
                            let stream = tokio::net::UnixStream::from_std(socket).unwrap();
                            let channel = tarpc::server::BaseChannel::with_defaults(transport::framed(stream));
                            let fake = server.clone();
                            tokio::spawn(channel.execute(fake.serve()).for_each(|response| async move { tokio::spawn(response); }));
                        }
                    }
                }
            });
        });
        Self {
            config: Config {
                path: path.to_str().unwrap().into(),
                interfaces_use: "eth0".into(),
                interfaces_ignore: String::new(),
            },
            _directory: directory,
            state,
            events,
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
fn endpoint() -> Value {
    json!({"address":"fe80::1","port":65535,"flow_info":0x12345678,"scope_id":u32::MAX})
}
fn sa_id() -> SaId {
    serde_json::from_value(json!({"src":endpoint(),"dst":endpoint(),"spi":u32::MAX,"protocol":51,"interface_id":0,"mark":{"value":u32::MAX,"mask":u32::MAX}})).unwrap()
}
fn selector() -> Value {
    json!({"kind":8,"dynamic":true,"from":"::","to":"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff","protocol":255,"from_port":0,"to_port":65535})
}
#[test]
fn complete_native_inputs_and_unsigned_outputs_over_tarpc_uds() {
    let fixture = Fixture::new(false);
    let (client, events) = Client::connect(&fixture.config).unwrap();
    assert_eq!(client.features(), 4);
    let limit = json!({"life":u64::MAX,"rekey":u64::MAX-1,"jitter":u64::MAX-2});
    let config = json!({
        "reqid":u32::MAX,"acquire_sequence":u32::MAX,"mode":6,
        "src_selectors":[selector()],"dst_selectors":[],"interface":"",
        "encryption":{"id":65535,"name":"future-cipher","key":[0,128,255]},
        "integrity":{"id":65534,"name":"future-auth","key":[255,0,254]},
        "lifetime":{"time":limit,"bytes":limit,"packets":limit},
        "replay_window":u32::MAX,"ipcomp":65535,"cpi":65535,"cpu":u32::MAX-1,
        "hw_offload":3,"security_label":[0,255,128],"esn":true,"udp_encapsulation":true,
        "output_mark":{"value":u32::MAX,"mask":u32::MAX},"tfc":u32::MAX,
        "copy_df":false,"copy_ecn":true,"copy_dscp":3,"iptfs_dont_fragment":true,
        "forward_icmp":true,"initiator":true,"inbound":true,"update":true,
    });
    let typed: SaConfig = serde_json::from_value(config.clone()).unwrap();
    let expected = json!({"id":sa_id(),"config":typed});
    let error = client
        .request(client.rpc().install_sa(
            api::context::current(),
            sa_id(),
            serde_json::from_value(config).unwrap(),
        ))
        .unwrap_err();
    assert_eq!(error.errno, Some(libc::EEXIST));
    assert_eq!(fixture.state.captured.lock().unwrap()[0], expected);
    let policy_id = json!({"direction":2,"src":selector(),"dst":selector(),"mark":{"value":42,"mask":255},"interface_id":u32::MAX,"interface":"eth0","security_label":[255,0,128]});
    let policy = json!({"kind":3,"priority":3,"manual_priority":u32::MAX,"hw_offload":3,"pcpu_acquires":true,"forward_icmp":true,"src":endpoint(),"dst":endpoint(),"sa":{"mode":6,"reqid":u32::MAX,"policy_count":u32::MAX,"esp":{"used":false,"spi":u32::MAX},"ah":{"used":true,"spi":u32::MAX-1},"ipcomp":{"transform":65535,"cpi":65535}}});
    client
        .request(client.rpc().install_policy(
            api::context::current(),
            serde_json::from_value(policy_id.clone()).unwrap(),
            serde_json::from_value(policy.clone()).unwrap(),
        ))
        .unwrap_err();
    assert_eq!(
        fixture.state.captured.lock().unwrap()[1],
        json!({"id":policy_id,"config":policy})
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
    drop(events);
}
#[test]
fn rejected_event_subscription_releases_empty_session() {
    let fixture = Fixture::new(true);
    assert!(Client::connect(&fixture.config).is_err());
    assert_eq!(fixture.state.closes.load(Ordering::Relaxed), 1);
}
#[test]
fn event_batches_wake_the_sync_client_and_disconnect_disables_control() {
    let fixture = Fixture::new(false);
    let (client, mut events) = Client::connect(&fixture.config).unwrap();
    let event = Event {
        kind: EventKind::Expire,
        expiry: Some(Expiry {
            protocol: 50,
            spi: u32::MAX,
            destination: serde_json::from_value(endpoint()).unwrap(),
            hard: true,
        }),
        acquire: None,
        mapping: None,
        address_changed: None,
    };
    fixture
        .events
        .blocking_send(vec![event.clone(); 300])
        .unwrap();
    let mut poll = [rustix::event::PollFd::new(
        &events,
        rustix::event::PollFlags::IN,
    )];
    assert_eq!(
        rustix::event::poll(
            &mut poll,
            Some(&rustix::time::Timespec {
                tv_sec: 2,
                tv_nsec: 0
            })
        )
        .unwrap(),
        1
    );
    for _ in 0..300 {
        let received = events.next_event().unwrap();
        assert_eq!(
            received.expiry.unwrap().destination,
            event.expiry.as_ref().unwrap().destination
        );
    }
    assert_eq!(
        events.next_event().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    let control = fixture
        .sockets
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    let watch = fixture
        .sockets
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    watch.shutdown(std::net::Shutdown::Both).unwrap();
    let mut poll = [rustix::event::PollFd::new(
        &events,
        rustix::event::PollFlags::IN,
    )];
    rustix::event::poll(
        &mut poll,
        Some(&rustix::time::Timespec {
            tv_sec: 2,
            tv_nsec: 0,
        }),
    )
    .unwrap();
    assert!(events.next_event().is_err());
    client.event_disconnected();
    assert!(client
        .request(client.rpc().query_sa(api::context::current(), sa_id(), 0))
        .is_err());
    drop(control);
}
