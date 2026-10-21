// SPDX-License-Identifier: GPL-2.0-or-later
use crate::{
    backend::{self, Backend},
    error::{invalid, unsupported},
    linux::{
        netlink::{Netlink, NlFamily, Notifications},
        xfrm,
    },
    rpc_api::*,
};
use neli::consts::rtnl::Rtm;
use std::{
    io,
    os::unix::net::UnixStream,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

const ROAM_DELAY: Duration = Duration::from_millis(100);
const REPAIR_DELAY: Duration = Duration::from_millis(100);
const AUDIT_INTERVAL: Duration = Duration::from_secs(5);
const ROUTE_CHANGED: u8 = 1;
const ADDRESS_CHANGED: u8 = 2;

pub struct Server {
    active: Mutex<Option<Arc<Session>>>,
    stopping: AtomicBool,
    session_failure: Arc<notification::Notification>,
    pub prefix: String,
    pub master_device: Option<String>,
    pub mtu: u32,
    pub interface_group: u32,
}
impl Server {
    pub fn new(
        prefix: String,
        master_device: Option<String>,
        mtu: u32,
        interface_group: u32,
    ) -> io::Result<Self> {
        Ok(Self {
            active: Mutex::new(None),
            stopping: AtomicBool::new(false),
            session_failure: Arc::new(notification::Notification::new()?),
            prefix,
            master_device,
            mtu,
            interface_group,
        })
    }
    /// Readable after an opened session fails, including a lost connection.
    pub fn session_failure(&self) -> &notification::Notification {
        &self.session_failure
    }
    pub fn shutdown(&self) -> io::Result<()> {
        let session = {
            let active = self.active.lock().unwrap();
            self.stopping.store(true, Ordering::Release);
            active.clone()
        };
        if let Some(session) = session {
            session.stop_workers();
            let _ = session.control.shutdown(std::net::Shutdown::Both);
            // Any in-flight mutation finishes before the final reconciliation.
            // Requests and event workers recheck closed after taking this lock.
            session.backend.lock().unwrap().shutdown()?;
        } else {
            // Ownership is namespace-wide even without an open charon session.
            Backend::new(
                self.prefix.clone(),
                self.master_device.clone(),
                self.mtu,
                self.interface_group,
                SessionConfig::default(),
            )?
            .shutdown()?;
        }
        Ok(())
    }
}
pub struct Session {
    backend: Mutex<Backend>,
    events: tokio::sync::mpsc::Sender<Option<Vec<Event>>>,
    event_wakeup: Arc<tokio::sync::Notify>,
    connected: AtomicBool,
    closed: AtomicBool,
    session_failure: Arc<notification::Notification>,
    roam: AtomicU8,
    network_changed: AtomicBool,
    repair_wakeup: SyncSender<()>,
    control: UnixStream,
    event_sockets: Mutex<Option<[Netlink; 2]>>,
}
impl Session {
    fn fail(&self) {
        if self.connected.swap(false, Ordering::AcqRel) {
            if let Err(error) = self.session_failure.notify() {
                eprintln!("kernel-daemon: session failure notification: {error}");
            }
        }
        let _ = self.repair_wakeup.try_send(());
        self.event_wakeup.notify_one();
        let _ = self.control.shutdown(std::net::Shutdown::Both);
    }
    fn stop_workers(&self) {
        self.connected.store(false, Ordering::Release);
        self.closed.store(true, Ordering::Release);
        let _ = self.repair_wakeup.try_send(());
        // Dropping the routers wakes the notification workers. The repair
        // worker was woken above; event polls also check the closed flag.
        self.event_sockets.lock().unwrap().take();
        let _ = self.events.try_send(None);
        self.event_wakeup.notify_one();
    }
    fn emit_events(&self, events: Vec<Event>) {
        if self.events.try_send(Some(events)).is_err() {
            self.fail();
        } else {
            self.event_wakeup.notify_one();
        }
    }
}
#[derive(Clone)]
pub struct Service(Arc<Connection>);
pub struct Connection {
    server: Arc<Server>,
    socket: UnixStream,
    control: Mutex<Option<Arc<Session>>>,
    watch: tokio::sync::Mutex<Option<Watch>>,
    event_wakeup: Arc<tokio::sync::Notify>,
}
struct Watch {
    session: Arc<Session>,
    receiver: tokio::sync::mpsc::Receiver<Option<Vec<Event>>>,
    next_roam: Instant,
    notified: bool,
}
impl Drop for Connection {
    fn drop(&mut self) {
        let control = self.control.get_mut().unwrap().as_ref();
        if let Some(s) = control {
            if !s.closed.load(Ordering::Acquire) {
                s.fail();
            }
        }
    }
}
impl std::ops::Deref for Service {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.0
    }
}
impl Service {
    pub fn new(server: Arc<Server>, socket: UnixStream) -> Self {
        Self(Arc::new(Connection {
            server,
            socket,
            control: Mutex::new(None),
            watch: tokio::sync::Mutex::new(None),
            event_wakeup: Arc::new(tokio::sync::Notify::new()),
        }))
    }
    /// One coalesced transport wakeup per change. XFRM batches wake immediately;
    /// a pending roam waits until its existing coalescing deadline, and a new
    /// XFRM batch can interrupt that wait. No backend lock is held while waiting.
    pub async fn next_notification(&self) -> Option<()> {
        loop {
            let due = {
                let mut guard = self.watch.lock().await;
                if let Some(watch) = guard.as_mut() {
                    let session = &watch.session;
                    if session.closed.load(Ordering::Acquire)
                        || !session.connected.load(Ordering::Acquire)
                    {
                        return None;
                    }
                    let roam = session.roam.load(Ordering::Relaxed) != 0;
                    if !watch.notified
                        && (!watch.receiver.is_empty() || roam && Instant::now() >= watch.next_roam)
                    {
                        watch.notified = true;
                        return Some(());
                    }
                    if !watch.notified && roam {
                        Some(watch.next_roam)
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            if let Some(due) = due {
                tokio::select! {
                    _ = self.event_wakeup.notified() => (),
                    _ = tokio::time::sleep_until(due.into()) => (),
                }
            } else {
                self.event_wakeup.notified().await;
            }
        }
    }
    fn request<T>(&self, operation: impl FnOnce(&mut Backend) -> io::Result<T>) -> Result<T> {
        let session = self
            .control
            .lock()
            .unwrap()
            .clone()
            .ok_or(Error::InvalidSession)?;
        let mut backend = session.backend.lock().unwrap();
        if !session.connected.load(Ordering::Acquire) || session.closed.load(Ordering::Acquire) {
            return Err(Error::InvalidSession);
        }
        if session.network_changed.swap(false, Ordering::Acquire) {
            backend.net.invalidate();
        }
        operation(&mut backend).map_err(Error::from)
    }
}
fn event_loop(session: Arc<Session>, xfrm: bool, notifications: Notifications) {
    for notification in notifications {
        if session.closed.load(Ordering::Acquire) {
            return;
        }
        let r = match notification {
            Ok(reply) => reply,
            Err(error) => {
                eprintln!(
                    "kernel-daemon: {} notification: {error}",
                    if xfrm { "XFRM" } else { "network" }
                );
                session.fail();
                return;
            }
        };
        if !xfrm {
            // A routing daemon can send thousands of notifications per second.
            // Keep one pending roam update, retaining address/link changes,
            // instead of queueing a separate IKE-wide job for every route.
            let kind = Rtm::from(r.kind);
            if matches!(kind, Rtm::Newlink | Rtm::Dellink) {
                let _ = session.repair_wakeup.try_send(());
            }
            let change = match kind {
                Rtm::Newlink | Rtm::Dellink | Rtm::Newaddr | Rtm::Deladdr => {
                    session.network_changed.store(true, Ordering::Release);
                    ADDRESS_CHANGED
                }
                _ => ROUTE_CHANGED,
            };
            if session.roam.fetch_or(change, Ordering::Relaxed) == 0 {
                session.event_wakeup.notify_one();
            }
            continue;
        }
        if matches!(
            r.kind,
            netlink_packet_xfrm::XFRM_MSG_NEWSA
                | netlink_packet_xfrm::XFRM_MSG_UPDSA
                | netlink_packet_xfrm::XFRM_MSG_DELSA
                | netlink_packet_xfrm::XFRM_MSG_FLUSHSA
                | netlink_packet_xfrm::XFRM_MSG_NEWPOLICY
                | netlink_packet_xfrm::XFRM_MSG_UPDPOLICY
                | netlink_packet_xfrm::XFRM_MSG_DELPOLICY
                | netlink_packet_xfrm::XFRM_MSG_FLUSHPOLICY
                | netlink_packet_xfrm::XFRM_MSG_POLEXPIRE
        ) {
            let _ = session.repair_wakeup.try_send(());
            continue;
        }
        let result = {
            let mut backend = session.backend.lock().unwrap();
            if session.closed.load(Ordering::Acquire) {
                return;
            }
            let Backend { sas, policies, .. } = &mut *backend;
            let result = xfrm::event(&r, sas, policies);
            if let Err(e) = backend.cleanup_interfaces() {
                eprintln!("kernel-daemon: interface cleanup: {e}");
            }
            result
        };
        match result {
            Ok(Some(event)) if session.connected.load(Ordering::Acquire) => {
                session.emit_events(vec![event]);
            }
            Err(e) => eprintln!("kernel-daemon: kernel event: {e}"),
            _ => (),
        }
    }
    if !session.closed.load(Ordering::Acquire) {
        session.fail();
    }
}
fn repair_loop(session: Arc<Session>, wakeup: Receiver<()>) {
    let mut next_audit = Instant::now() + AUDIT_INTERVAL;
    while session.connected.load(Ordering::Acquire) && !session.closed.load(Ordering::Acquire) {
        match wakeup.recv_timeout(next_audit.saturating_duration_since(Instant::now())) {
            Ok(()) => {
                // Bound the delay even during continuous policy/link updates.
                next_audit = next_audit.min(Instant::now() + REPAIR_DELAY);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => (),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if Instant::now() < next_audit {
            continue;
        }
        // Keep this lock through inventory, retirement and policy/link repairs.
        // Install/delete/rekey requests use this same lock.
        let mut backend = session.backend.lock().unwrap();
        if !session.connected.load(Ordering::Acquire) || session.closed.load(Ordering::Acquire) {
            break;
        }
        match backend.reconcile_sas() {
            Ok(changes) => {
                if let Some(error) = changes.cleanup_error {
                    eprintln!("kernel-daemon: SA cleanup: {error}");
                }
                // One bounded queue entry per inventory, so a flush of
                // hundreds of SAs cannot overflow the queue with expirations.
                let events: Vec<_> = changes
                    .expired
                    .into_iter()
                    .map(|id| Event {
                        kind: EventKind::Expire,
                        expiry: Some(Expiry {
                            protocol: id.proto,
                            spi: id.spi,
                            destination: id.dst,
                            hard: true,
                        }),
                        acquire: None,
                        mapping: None,
                        address_changed: None,
                    })
                    .collect();
                if !events.is_empty() {
                    session.emit_events(events);
                }
            }
            Err(error) => eprintln!("kernel-daemon: SA inventory: {error}"),
        }
        if let Err(error) = backend.reconcile_interfaces() {
            eprintln!("kernel-daemon: interface reconciliation: {error}");
        }
        if let Err(error) = backend.policies.reconcile() {
            eprintln!("kernel-daemon: policy reconciliation: {error}");
        }
        next_audit = Instant::now() + AUDIT_INTERVAL;
    }
}
impl Kernel for Service {
    async fn open_session(
        self,
        _: tarpc::context::Context,
        config: SessionConfig,
    ) -> Result<SessionInfo> {
        let mut watch = self.watch.lock().await;
        let mut active = self.server.active.lock().unwrap();
        if self.server.stopping.load(Ordering::Acquire) {
            return Err(Error::InvalidSession);
        }
        if active.is_some() || self.control.lock().unwrap().is_some() {
            return Err(Error::SessionBusy);
        }
        let create = || -> io::Result<_> {
            if config.interfaces_use.len() > 4096 || config.interfaces_ignore.len() > 4096 {
                return Err(invalid());
            }
            // Subscribe before discovery so startup changes remain observable.
            let (route_socket, route) =
                Netlink::subscribe(NlFamily::Route, 1 | 0x10 | 0x100 | 0x40 | 0x400)?;
            let mut backend = Backend::new(
                self.server.prefix.clone(),
                self.server.master_device.clone(),
                self.server.mtu,
                self.server.interface_group,
                config,
            )?;
            backend.policies.reconcile()?;
            backend.sas.clear()?;
            backend.reconcile_interfaces()?;
            let (xfrm_socket, xfrm) = Netlink::subscribe(NlFamily::Xfrm, 1 | 2 | 4 | 8 | 128)?;
            let features = backend.sas.features();
            let (tx, rx) = tokio::sync::mpsc::channel(256);
            let (repair_wakeup, repair_receiver) = mpsc::sync_channel(1);
            let session = Arc::new(Session {
                backend: Mutex::new(backend),
                events: tx,
                event_wakeup: self.event_wakeup.clone(),
                connected: AtomicBool::new(true),
                closed: AtomicBool::new(false),
                session_failure: self.server.session_failure.clone(),
                roam: AtomicU8::new(0),
                network_changed: AtomicBool::new(false),
                repair_wakeup,
                control: self.socket.try_clone()?,
                event_sockets: Mutex::new(Some([xfrm_socket, route_socket])),
            });
            Ok((session, rx, features, xfrm, route, repair_receiver))
        };
        let (session, receiver, features, xfrm, route, repair_receiver) = create()?;
        *active = Some(session.clone());
        *self.control.lock().unwrap() = Some(session.clone());
        *watch = Some(Watch {
            session: session.clone(),
            receiver,
            next_roam: Instant::now() + ROAM_DELAY,
            notified: false,
        });
        let worker = session.clone();
        thread::spawn(move || event_loop(worker, true, xfrm));
        let worker = session.clone();
        thread::spawn(move || repair_loop(worker, repair_receiver));
        thread::spawn(move || event_loop(session, false, route));
        Ok(SessionInfo { features })
    }
    async fn close_session(self, _: tarpc::context::Context) -> Result<()> {
        self.request(|backend| {
            backend.close()?;
            self.control
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .stop_workers();
            *self.server.active.lock().unwrap() = None;
            Ok(())
        })
    }
    async fn next_events(self, _: tarpc::context::Context) -> Result<Vec<Event>> {
        let mut guard = self.watch.lock().await;
        let watch = guard.as_mut().ok_or(Error::InvalidSession)?;
        let session = &watch.session;
        if !session.connected.load(Ordering::Acquire) || session.closed.load(Ordering::Acquire) {
            return Err(Error::InvalidSession);
        }
        watch.notified = false;
        let mut batch = match watch.receiver.try_recv() {
            Ok(Some(batch)) => batch,
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => Vec::new(),
            _ => return Err(Error::InvalidSession),
        };
        if Instant::now() >= watch.next_roam {
            watch.next_roam = Instant::now() + ROAM_DELAY;
            let changes = session.roam.swap(0, Ordering::Relaxed);
            if changes != 0 {
                batch.push(Event {
                    kind: EventKind::Roam,
                    address_changed: Some(changes & ADDRESS_CHANGED != 0),
                    expiry: None,
                    acquire: None,
                    mapping: None,
                });
            }
        }
        self.event_wakeup.notify_one();
        Ok(batch)
    }

    async fn allocate_spi(
        self,
        _: tarpc::context::Context,
        src: Endpoint,
        dst: Endpoint,
        protocol: u8,
        minimum: u32,
        maximum: u32,
    ) -> Result<u32> {
        self.request(|backend| {
            if protocol != 50 {
                return Err(unsupported());
            }
            let (src, dst) = (
                backend::validate_endpoint(src)?,
                backend::validate_endpoint(dst)?,
            );
            if src.family() != dst.family() || minimum < 256 || minimum > maximum {
                return Err(invalid());
            }
            backend.sas.allocate(src, dst, protocol, minimum, maximum)
        })
    }
    async fn allocate_cpi(
        self,
        _: tarpc::context::Context,
        _src: Endpoint,
        _dst: Endpoint,
    ) -> Result<u16> {
        self.request(|_| Err(unsupported()))
    }
    async fn install_sa(
        self,
        _: tarpc::context::Context,
        id: SaId,
        config: SaConfig,
    ) -> Result<()> {
        self.request(|backend| backend.install_sa(id, config))
    }
    async fn update_sa(
        self,
        _: tarpc::context::Context,
        _id: SaId,
        _config: SaUpdate,
    ) -> Result<()> {
        self.request(|_| Err(unsupported()))
    }
    async fn query_sa(self, _: tarpc::context::Context, id: SaId, cpi: u16) -> Result<SaUsage> {
        self.request(|backend| {
            if cpi != 0 {
                return Err(unsupported());
            }
            backend.sas.query(&backend::sa_id(id)?)
        })
    }
    async fn remove_sa(self, _: tarpc::context::Context, id: SaId, cpi: u16) -> Result<()> {
        self.request(|backend| {
            if cpi != 0 {
                return Err(unsupported());
            }
            backend.remove_sa(id)
        })
    }
    async fn flush_sas(self, _: tarpc::context::Context) -> Result<()> {
        self.request(Backend::flush_sas)
    }
    async fn install_policy(
        self,
        _: tarpc::context::Context,
        id: PolicyId,
        config: PolicyConfig,
    ) -> Result<()> {
        self.request(|backend| {
            backend
                .policies
                .add_policy(backend::policy_id(id)?, backend::policy_config(config)?)
        })
    }
    async fn remove_policy(
        self,
        _: tarpc::context::Context,
        id: PolicyId,
        config: PolicyConfig,
    ) -> Result<()> {
        self.request(|backend| {
            backend
                .policies
                .delete_policy(&backend::policy_id(id)?, &backend::policy_config(config)?)
        })
    }
    async fn query_policy(self, _: tarpc::context::Context, id: PolicyId) -> Result<u64> {
        self.request(|backend| backend.policies.query_policy(&backend::policy_id(id)?))
    }
    async fn flush_policies(self, _: tarpc::context::Context) -> Result<()> {
        self.request(|backend| backend.policies.flush_policies())
    }
    async fn bypass_port(self, _: tarpc::context::Context, family: u16, port: u16) -> Result<()> {
        self.request(|backend| {
            if ![libc::AF_INET as u16, libc::AF_INET6 as u16].contains(&family) || port < 1024 {
                return Err(invalid());
            }
            backend.policies.port_bypass(family, port)
        })
    }
    async fn get_source_address(
        self,
        _: tarpc::context::Context,
        destination: Endpoint,
        source: Option<Endpoint>,
    ) -> Result<Endpoint> {
        self.request(|backend| {
            let src = source.map(backend::validate_endpoint).transpose()?;
            let (host, _, _) =
                backend
                    .net
                    .lookup(&backend::validate_endpoint(destination)?, src.as_ref(), -1)?;
            Ok(host)
        })
    }
    async fn get_next_hop(
        self,
        _: tarpc::context::Context,
        destination: Endpoint,
        source: Option<Endpoint>,
        prefix: Option<i32>,
    ) -> Result<NextHop> {
        self.request(|backend| {
            let dst = backend::validate_endpoint(destination)?;
            let src = source.map(backend::validate_endpoint).transpose()?;
            let prefix = prefix.unwrap_or(-1);
            if prefix < -1 || prefix > dst.bits().into() {
                return Err(invalid());
            }
            let (_, gateway, interface) = backend.net.lookup(&dst, src.as_ref(), prefix)?;
            Ok(NextHop { gateway, interface })
        })
    }
    async fn get_interface(self, _: tarpc::context::Context, address: Endpoint) -> Result<String> {
        self.request(|backend| backend.net.interface(&backend::validate_endpoint(address)?))
    }
    async fn list_addresses(self, _: tarpc::context::Context, which: i32) -> Result<Vec<Endpoint>> {
        self.request(|backend| {
            backend
                .net
                .enumerate(u32::try_from(which).map_err(|_| invalid())?)
        })
    }
    async fn list_subnets(self, _: tarpc::context::Context) -> Result<Vec<Subnet>> {
        self.request(|backend| {
            backend.net.subnets().map(|subnets| {
                subnets
                    .into_iter()
                    .map(|(address, prefix, interface)| Subnet {
                        address,
                        prefix,
                        interface,
                    })
                    .collect()
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires root; creates a network namespace"]
    async fn failed_session_wakes_shutdown_without_waiting_for_connection_drop() {
        let _namespace = crate::test_netns::Netns::new();
        let server = Arc::new(Server::new("tst".into(), None, 1400, 17227).unwrap());
        let (socket, _peer) = UnixStream::pair().unwrap();
        let service = Service::new(server.clone(), socket);
        service
            .clone()
            .open_session(
                context::current(),
                SessionConfig {
                    interfaces_use: String::new(),
                    interfaces_ignore: String::new(),
                    ..SessionConfig::default()
                },
            )
            .await
            .unwrap();
        let session = service.control.lock().unwrap().clone().unwrap();
        assert!(!server.session_failure().drain().unwrap());
        // Losing an event invalidates the whole session, even while the
        // connection and service objects are still alive.
        for _ in 0..=256 {
            session.emit_events(Vec::new());
        }
        assert!(server.session_failure().drain().unwrap());
        assert!(!session.connected.load(Ordering::Acquire));
        assert!(matches!(
            service.clone().next_events(context::current()).await,
            Err(Error::InvalidSession)
        ));
        server.shutdown().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires root; creates a network namespace"]
    async fn urgent_push_preserves_the_pending_roam_deadline() {
        let _namespace = crate::test_netns::Netns::new();
        let server = Arc::new(Server::new("tst".into(), None, 1400, 17227).unwrap());
        let (socket, _peer) = UnixStream::pair().unwrap();
        let service = Service::new(server.clone(), socket);
        service
            .clone()
            .open_session(
                context::current(),
                SessionConfig {
                    interfaces_use: String::new(),
                    interfaces_ignore: String::new(),
                    ..SessionConfig::default()
                },
            )
            .await
            .unwrap();
        let session = {
            let mut guard = service.watch.lock().await;
            let watch = guard.as_mut().unwrap();
            watch.next_roam = Instant::now() + Duration::from_millis(150);
            watch.session.roam.store(ROUTE_CHANGED, Ordering::Relaxed);
            watch.session.clone()
        };
        session.event_wakeup.notify_one();
        let pending = tokio::spawn({
            let service = service.clone();
            async move { service.next_notification().await }
        });
        tokio::time::sleep(Duration::from_millis(5)).await;
        session.emit_events(vec![Event {
            kind: EventKind::Expire,
            expiry: Some(Expiry {
                protocol: 50,
                spi: 7,
                destination: Endpoint {
                    address: "192.0.2.1".parse().unwrap(),
                    port: 0,
                    flow_info: 0,
                    scope_id: 0,
                },
                hard: true,
            }),
            acquire: None,
            mapping: None,
            address_changed: None,
        }]);
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(100), pending)
                .await
                .unwrap()
                .unwrap(),
            Some(())
        );
        let batch = service
            .clone()
            .next_events(context::current())
            .await
            .unwrap();
        assert_eq!(batch.len(), 1);
        assert!(matches!(batch[0].kind, EventKind::Expire));
        // No further route change or XFRM event arrives. The original pending
        // roam must still produce its own push at the coalescing deadline.
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), service.next_notification())
                .await
                .unwrap(),
            Some(())
        );
        let batch = service
            .clone()
            .next_events(context::current())
            .await
            .unwrap();
        assert_eq!(batch.len(), 1);
        assert!(matches!(batch[0].kind, EventKind::Roam));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), service.next_notification())
                .await
                .is_err(),
            "no periodic pushes when idle"
        );
        service.close_session(context::current()).await.unwrap();
        server.shutdown().unwrap();
    }
}
