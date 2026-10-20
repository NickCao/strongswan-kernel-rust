// SPDX-License-Identifier: GPL-2.0-or-later
use crate::{
    backend::{self, Backend},
    error::{invalid, unsupported},
    linux::{
        netlink::{Netlink, NlFamily, Notifications},
        xfrm,
    },
    rpc_api::*,
    transport,
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
    ) -> Self {
        Self {
            active: Mutex::new(None),
            stopping: AtomicBool::new(false),
            prefix,
            master_device,
            mtu,
            interface_group,
        }
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
                String::new(),
                String::new(),
            )?
            .shutdown()?;
        }
        Ok(())
    }
}
pub struct Session {
    uid: u32,
    pid: i32,
    token: SessionToken,
    backend: Mutex<Backend>,
    events: tokio::sync::mpsc::Sender<Option<Vec<Event>>>,
    receiver: Mutex<Option<tokio::sync::mpsc::Receiver<Option<Vec<Event>>>>>,
    connected: AtomicBool,
    closed: AtomicBool,
    roam: AtomicU8,
    network_changed: AtomicBool,
    repair_wakeup: SyncSender<()>,
    control: UnixStream,
    event_sockets: Mutex<Option<[Netlink; 2]>>,
}
impl Session {
    fn fail(&self) {
        self.connected.store(false, Ordering::Release);
        let _ = self.repair_wakeup.try_send(());
        let _ = self.control.shutdown(std::net::Shutdown::Both);
    }
    fn stop_workers(&self) {
        self.connected.store(false, Ordering::Release);
        self.closed.store(true, Ordering::Release);
        let _ = self.repair_wakeup.try_send(());
        // Dropping the routers wakes the notification workers. WatchEvents
        // and the repair worker are woken separately below and above.
        self.event_sockets.lock().unwrap().take();
        let _ = self.events.try_send(None);
    }
}
#[derive(Clone)]
pub struct Service(Arc<Connection>);
pub struct Connection {
    server: Arc<Server>,
    socket: UnixStream,
    peer: transport::Peer,
    control: Mutex<Option<Arc<Session>>>,
    watch: tokio::sync::Mutex<Option<Watch>>,
}
struct Watch {
    session: Arc<Session>,
    receiver: tokio::sync::mpsc::Receiver<Option<Vec<Event>>>,
    next_roam: Instant,
}
impl Drop for Connection {
    fn drop(&mut self) {
        let control = self.control.get_mut().unwrap().as_ref();
        let watch = self.watch.get_mut().as_ref().map(|w| &w.session);
        if let Some(s) = control.or(watch) {
            if !s.closed.load(Ordering::Acquire) {
                s.fail();
                eprintln!("kernel-daemon: client disconnected; preserving tunnel objects; replacement sessions require daemon restart");
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
    pub fn new(server: Arc<Server>, socket: UnixStream, peer: transport::Peer) -> Self {
        Self(Arc::new(Connection {
            server,
            socket,
            peer,
            control: Mutex::new(None),
            watch: tokio::sync::Mutex::new(None),
        }))
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
            session.roam.fetch_or(change, Ordering::Relaxed);
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
                if session.events.try_send(Some(vec![event])).is_err() {
                    session.fail();
                }
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
                            destination: backend::endpoint(id.dst),
                            hard: true,
                        }),
                        acquire: None,
                        mapping: None,
                        address_changed: None,
                    })
                    .collect();
                if !events.is_empty() && session.events.try_send(Some(events)).is_err() {
                    session.fail();
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
                config.interfaces_use,
                config.interfaces_ignore,
            )?;
            backend.policies.reconcile()?;
            backend.sas.clear()?;
            backend.reconcile_interfaces()?;
            let (xfrm_socket, xfrm) = Netlink::subscribe(NlFamily::Xfrm, 1 | 2 | 4 | 8 | 128)?;
            let token = rand::random::<SessionToken>();
            let features = backend.sas.features();
            let (tx, rx) = tokio::sync::mpsc::channel(256);
            let (repair_wakeup, repair_receiver) = mpsc::sync_channel(1);
            let session = Arc::new(Session {
                uid: self.peer.uid,
                pid: self.peer.pid,
                token,
                backend: Mutex::new(backend),
                events: tx,
                receiver: Mutex::new(Some(rx)),
                connected: AtomicBool::new(true),
                closed: AtomicBool::new(false),
                roam: AtomicU8::new(0),
                network_changed: AtomicBool::new(false),
                repair_wakeup,
                control: self.socket.try_clone()?,
                event_sockets: Mutex::new(Some([xfrm_socket, route_socket])),
            });
            Ok((session, token, features, xfrm, route, repair_receiver))
        };
        let (session, token, features, xfrm, route, repair_receiver) = create()?;
        *active = Some(session.clone());
        *self.control.lock().unwrap() = Some(session.clone());
        let worker = session.clone();
        thread::spawn(move || event_loop(worker, true, xfrm));
        let worker = session.clone();
        thread::spawn(move || repair_loop(worker, repair_receiver));
        thread::spawn(move || event_loop(session, false, route));
        Ok(SessionInfo { token, features })
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
    async fn subscribe_events(self, _: tarpc::context::Context, token: SessionToken) -> Result<()> {
        let mut watch = self.watch.lock().await;
        if watch.is_some() {
            return Err(Error::SessionBusy);
        }
        let session = self
            .server
            .active
            .lock()
            .unwrap()
            .clone()
            .ok_or(Error::InvalidSession)?;
        if session.uid != self.peer.uid
            || session.pid != self.peer.pid
            || session.token != token
            || !session.connected.load(Ordering::Acquire)
        {
            return Err(Error::InvalidSession);
        }
        let receiver = session
            .receiver
            .lock()
            .unwrap()
            .take()
            .ok_or(Error::SessionBusy)?;
        *watch = Some(Watch {
            session,
            receiver,
            next_roam: Instant::now() + ROAM_DELAY,
        });
        Ok(())
    }
    async fn next_events(self, _: tarpc::context::Context) -> Result<Vec<Event>> {
        let mut guard = self.watch.lock().await;
        let watch = guard.as_mut().ok_or(Error::InvalidSession)?;
        let heartbeat = tokio::time::sleep(Duration::from_secs(30));
        tokio::pin!(heartbeat);
        loop {
            let session = &watch.session;
            if !session.connected.load(Ordering::Acquire) || session.closed.load(Ordering::Acquire)
            {
                return Err(Error::InvalidSession);
            }
            if Instant::now() >= watch.next_roam {
                watch.next_roam = Instant::now() + ROAM_DELAY;
                let changes = session.roam.swap(0, Ordering::Relaxed);
                if changes != 0 {
                    return Ok(vec![Event {
                        kind: EventKind::Roam,
                        address_changed: Some(changes & ADDRESS_CHANGED != 0),
                        expiry: None,
                        acquire: None,
                        mapping: None,
                    }]);
                }
            }
            tokio::select! {
                batch = watch.receiver.recv() => return batch.flatten().ok_or(Error::InvalidSession),
                _ = tokio::time::sleep_until(watch.next_roam.into()) => (),
                // Keep a quiet subscription within tarpc's request deadline.
                // No backend inventory or mutation is triggered by heartbeats.
                _ = &mut heartbeat => return Ok(Vec::new()),
            }
        }
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
            let (src, dst) = (backend::host(src)?, backend::host(dst)?);
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
            let usage = backend.sas.query(&backend::sa_id(id)?)?;
            Ok(SaUsage {
                bytes: usage.bytes,
                packets: usage.packets,
                last_use: usage.last_use,
            })
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
            let src = source.map(backend::host).transpose()?;
            let (host, _, _) =
                backend
                    .net
                    .lookup(&backend::host(destination)?, src.as_ref(), -1)?;
            // Preserve the full caller endpoint when the backend confirms it.
            Ok(source
                .filter(|s| s.address == host.ip)
                .unwrap_or_else(|| backend::endpoint(host)))
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
            let dst = backend::host(destination)?;
            let src = source.map(backend::host).transpose()?;
            let prefix = prefix.unwrap_or(-1);
            if prefix < -1 || prefix > dst.bits().into() {
                return Err(invalid());
            }
            let (_, gateway, interface) = backend.net.lookup(&dst, src.as_ref(), prefix)?;
            Ok(NextHop {
                gateway: backend::endpoint(gateway),
                interface,
            })
        })
    }
    async fn get_interface(self, _: tarpc::context::Context, address: Endpoint) -> Result<String> {
        self.request(|backend| backend.net.interface(&backend::host(address)?))
    }
    async fn list_addresses(self, _: tarpc::context::Context, which: i32) -> Result<Vec<Endpoint>> {
        self.request(|backend| {
            backend
                .net
                .enumerate(u32::try_from(which).map_err(|_| invalid())?)
                .map(|hosts| hosts.into_iter().map(backend::endpoint).collect())
        })
    }
    async fn list_subnets(self, _: tarpc::context::Context) -> Result<Vec<Subnet>> {
        self.request(|backend| {
            backend.net.subnets().map(|subnets| {
                subnets
                    .into_iter()
                    .map(|(address, prefix, interface)| Subnet {
                        address: backend::endpoint(address),
                        prefix,
                        interface,
                    })
                    .collect()
            })
        })
    }
}
