// SPDX-License-Identifier: GPL-2.0-or-later
//! Session ownership and lifecycle shared by RPC dispatch and worker modules.
mod events;
mod reconcile;
mod rpc;

use self::events::Watch;
use crate::{
    backend::Backend,
    error::invalid,
    linux::netlink::{Netlink, NlFamily},
    rpc_api::{notification, Error, Event, Result, SessionConfig, SessionInfo},
};
use std::{
    io,
    os::unix::net::UnixStream,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc::{self, SyncSender},
        Arc, Mutex,
    },
    thread,
};

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
    async fn open(&self, config: SessionConfig) -> Result<SessionInfo> {
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
        *watch = Some(Watch::new(session.clone(), receiver));
        let worker = session.clone();
        thread::spawn(move || events::run(worker, true, xfrm));
        let worker = session.clone();
        thread::spawn(move || reconcile::run(worker, repair_receiver));
        thread::spawn(move || events::run(session, false, route));
        Ok(SessionInfo { features })
    }
    fn close(&self) -> Result<()> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc_api::{context, Kernel};

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
}
