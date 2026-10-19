// SPDX-License-Identifier: GPL-2.0-or-later
use crate::{
    backend::{self, Backend},
    error::invalid,
    netlink::{Netlink, NlFamily, Notifications},
    rpc_api::*,
    transport,
};
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
const ROUTE_CHANGED: u8 = 1;
const ADDRESS_CHANGED: u8 = 2;

pub struct Server {
    pub active: Mutex<Option<Arc<Session>>>,
    pub prefix: String,
    pub master_device: Option<String>,
    pub mtu: u32,
}
pub struct Session {
    uid: u32,
    pid: i32,
    token: String,
    backend: Mutex<Backend>,
    events: SyncSender<Option<Event>>,
    receiver: Mutex<Option<Receiver<Option<Event>>>>,
    connected: AtomicBool,
    closed: AtomicBool,
    roam: AtomicU8,
    network_changed: AtomicBool,
    control: UnixStream,
    event_sockets: Mutex<Option<[Netlink; 2]>>,
}
impl Session {
    fn fail(&self) {
        self.connected.store(false, Ordering::Release);
        let _ = self.control.shutdown(std::net::Shutdown::Both);
    }
}
pub struct Service {
    pub server: Arc<Server>,
    pub socket: UnixStream,
    pub peer: transport::Peer,
    pub control: Mutex<Option<Arc<Session>>>,
}
impl Drop for Service {
    fn drop(&mut self) {
        if let Some(s) = self.control.lock().unwrap().as_ref() {
            if !s.closed.load(Ordering::Acquire) {
                s.fail();
                eprintln!("kernel-daemon: client disconnected; preserving tunnel objects; replacement sessions require daemon restart");
            }
        }
    }
}
fn event_loop(session: Arc<Session>, xfrm: bool, notifications: Notifications) {
    for notification in notifications {
        if session.closed.load(Ordering::Acquire) {
            return;
        }
        let r = match notification {
            Ok(reply) => reply,
            Err(_) => {
                session.fail();
                return;
            }
        };
        if !xfrm {
            // A routing daemon can send thousands of notifications per second.
            // Keep one pending roam update, retaining address/link changes,
            // instead of queueing a separate IKE-wide job for every route.
            let change = if [16, 17, 20, 21].contains(&r.kind) {
                session.network_changed.store(true, Ordering::Release);
                ADDRESS_CHANGED
            } else {
                ROUTE_CHANGED
            };
            session.roam.fetch_or(change, Ordering::Relaxed);
            continue;
        }
        let result = {
            let mut backend = session.backend.lock().unwrap();
            let result = backend.xfrm.event(&r);
            if let Err(e) = backend.reconcile_interfaces() {
                eprintln!("kernel-daemon: interface cleanup: {e}");
            }
            result
        };
        match result {
            Ok(Some(event)) if session.connected.load(Ordering::Acquire) => {
                if session.events.try_send(Some(event)).is_err() {
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
macro_rules! request {
    ($this:expr, $call:expr, $b:ident, $body:expr, $reply:expr) => {{
        let session = $this.control.lock().unwrap().clone();
        match session {
            Some(s) if s.connected.load(Ordering::Acquire) && !s.closed.load(Ordering::Acquire) => {
                let result = {
                    let mut guard = s.backend.lock().unwrap();
                    let $b = &mut *guard;
                    if s.network_changed.swap(false, Ordering::Acquire) {
                        $b.net.invalidate();
                    }
                    {
                        #[allow(clippy::redundant_closure_call)]
                        let result = (|| -> io::Result<_> { $body })();
                        result
                    }
                };
                match result {
                    Ok(value) => ($reply)($call, value),
                    Err(e) => {
                        $call.reply_kernel_error(e.raw_os_error().unwrap_or(libc::EINVAL).into())
                    }
                }
            }
            _ => $call.reply_invalid_session(),
        }
    }};
}
impl VarlinkInterface for Service {
    fn open_session(
        &self,
        call: &mut dyn Call_OpenSession,
        interfaces_use: String,
        interfaces_ignore: String,
    ) -> varlink::Result<()> {
        if call.is_oneway() || call.wants_more() {
            return call.reply_invalid_parameter("OpenSession".into());
        }
        let mut active = self.server.active.lock().unwrap();
        if active.is_some() || self.control.lock().unwrap().is_some() {
            return call.reply_session_busy();
        }
        let create = || -> io::Result<_> {
            if interfaces_use.len() > 4096 || interfaces_ignore.len() > 4096 {
                return Err(invalid());
            }
            // Subscribe before the first discovery snapshot so changes during
            // startup are retained and invalidate it on the next request.
            let (route_socket, route) =
                Netlink::subscribe(NlFamily::Route, 1 | 0x10 | 0x100 | 0x40 | 0x400)?;
            let backend = Backend::new(
                self.server.prefix.clone(),
                self.server.master_device.clone(),
                self.server.mtu,
                interfaces_use,
                interfaces_ignore,
            )?;
            let (xfrm_socket, xfrm) = Netlink::subscribe(NlFamily::Xfrm, 1 | 2 | 128)?;
            let token = hex::encode(rand::random::<[u8; 32]>());
            let features = backend.xfrm.features().into();
            let (tx, rx) = mpsc::sync_channel(256);
            let s = Arc::new(Session {
                uid: self.peer.uid,
                pid: self.peer.pid,
                token: token.clone(),
                backend: Mutex::new(backend),
                events: tx,
                receiver: Mutex::new(Some(rx)),
                connected: AtomicBool::new(true),
                closed: AtomicBool::new(false),
                roam: AtomicU8::new(0),
                network_changed: AtomicBool::new(false),
                control: self.socket.try_clone()?,
                event_sockets: Mutex::new(Some([xfrm_socket, route_socket])),
            });
            Ok((s, token, features, xfrm, route))
        };
        let (s, token, features, xfrm, route) = match create() {
            Ok(v) => v,
            Err(e) => return call.reply_kernel_error(e.raw_os_error().unwrap_or(libc::EIO).into()),
        };
        *active = Some(s.clone());
        *self.control.lock().unwrap() = Some(s.clone());
        let session = s.clone();
        thread::spawn(move || event_loop(session, true, xfrm));
        thread::spawn(move || event_loop(s, false, route));
        call.reply(token, features)
    }
    fn close_session(&self, call: &mut dyn Call_CloseSession) -> varlink::Result<()> {
        request!(
            self,
            call,
            b,
            {
                b.close()?;
                let s = self.control.lock().unwrap().as_ref().unwrap().clone();
                s.connected.store(false, Ordering::Release);
                s.closed.store(true, Ordering::Release);
                // Dropping the neli routers stops their receive threads and
                // closes the notification streams, waking our event workers.
                s.event_sockets.lock().unwrap().take();
                // Wake WatchEvents immediately so clean, rapid restarts do not
                // exhaust the bounded connection slots waiting for its timeout.
                let _ = s.events.try_send(None);
                *self.server.active.lock().unwrap() = None;
                Ok(())
            },
            |c: &mut dyn Call_CloseSession, ()| c.reply()
        )
    }
    fn watch_events(&self, call: &mut dyn Call_WatchEvents, token: String) -> varlink::Result<()> {
        if !call.wants_more() || call.is_oneway() {
            return call.reply_invalid_parameter("more".into());
        }
        let session = self.server.active.lock().unwrap().clone();
        let s = match session {
            Some(s)
                if s.uid == self.peer.uid
                    && s.pid == self.peer.pid
                    && s.token == token
                    && s.connected.load(Ordering::Acquire) =>
            {
                s
            }
            _ => return call.reply_invalid_session(),
        };
        let receiver = match s.receiver.lock().unwrap().take() {
            Some(r) => r,
            None => return call.reply_session_busy(),
        };
        call.set_continues(true);
        if let Err(e) = call.reply(Event {
            kind: Event_kind::ready,
            expiry: None,
            acquire: None,
            mapping: None,
            addressChanged: None,
        }) {
            s.fail();
            return Err(e);
        }
        let mut next_roam = Instant::now() + ROAM_DELAY;
        while s.connected.load(Ordering::Acquire) && !s.closed.load(Ordering::Acquire) {
            match receiver.recv_timeout(next_roam.saturating_duration_since(Instant::now())) {
                Ok(Some(event)) => {
                    if s.closed.load(Ordering::Acquire) {
                        break;
                    }
                    if let Err(e) = call.reply(event) {
                        s.fail();
                        return Err(e);
                    }
                }
                Ok(None) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => (),
                Err(_) => break,
            }
            if Instant::now() >= next_roam {
                let changes = s.roam.swap(0, Ordering::Relaxed);
                if changes != 0 {
                    if let Err(e) = call.reply(Event {
                        kind: Event_kind::roam,
                        addressChanged: Some(changes & ADDRESS_CHANGED != 0),
                        expiry: None,
                        acquire: None,
                        mapping: None,
                    }) {
                        s.fail();
                        return Err(e);
                    }
                }
                next_roam = Instant::now() + ROAM_DELAY;
            }
            if transport::disconnected(&self.socket) {
                s.fail();
                break;
            }
        }
        call.set_continues(false);
        call.reply_invalid_session()
    }
    fn allocate_spi(
        &self,
        call: &mut dyn Call_AllocateSpi,
        src: Endpoint,
        dst: Endpoint,
        minimum: i64,
        maximum: i64,
    ) -> varlink::Result<()> {
        request!(
            self,
            call,
            b,
            {
                let (src, dst) = (backend::host(src)?, backend::host(dst)?);
                let (min, max): (u32, u32) = (backend::number(minimum)?, backend::number(maximum)?);
                if src.family() != dst.family() || min < 256 || min > max {
                    return Err(invalid());
                }
                b.xfrm.allocate(src, dst, 50, min, max)
            },
            |c: &mut dyn Call_AllocateSpi, spi: u32| c.reply(spi.into())
        )
    }
    fn install_sa(
        &self,
        call: &mut dyn Call_InstallSa,
        id: SaId,
        config: SaConfig,
    ) -> varlink::Result<()> {
        request!(
            self,
            call,
            b,
            b.install_sa(id, config),
            |c: &mut dyn Call_InstallSa, ()| c.reply()
        )
    }
    fn remove_sa(&self, call: &mut dyn Call_RemoveSa, id: SaId) -> varlink::Result<()> {
        request!(
            self,
            call,
            b,
            b.remove_sa(id),
            |c: &mut dyn Call_RemoveSa, ()| c.reply()
        )
    }
    fn query_sa(&self, call: &mut dyn Call_QuerySa, id: SaId) -> varlink::Result<()> {
        request!(
            self,
            call,
            b,
            b.xfrm.query_sa(&backend::sa_id(id)?),
            |c: &mut dyn Call_QuerySa, (bytes, packets, last): (u64, u64, u64)| c.reply(
                bytes.to_string(),
                packets.to_string(),
                last as i64
            )
        )
    }
    fn flush_sas(&self, call: &mut dyn Call_FlushSas) -> varlink::Result<()> {
        request!(
            self,
            call,
            b,
            b.flush_sas(),
            |c: &mut dyn Call_FlushSas, ()| c.reply()
        )
    }
    fn install_policy(
        &self,
        call: &mut dyn Call_InstallPolicy,
        id: PolicyId,
        config: PolicyConfig,
    ) -> varlink::Result<()> {
        request!(
            self,
            call,
            b,
            b.xfrm
                .add_policy(backend::policy_id(id)?, backend::policy_config(config)?,),
            |c: &mut dyn Call_InstallPolicy, ()| c.reply()
        )
    }
    fn remove_policy(
        &self,
        call: &mut dyn Call_RemovePolicy,
        id: PolicyId,
        config: PolicyConfig,
    ) -> varlink::Result<()> {
        request!(
            self,
            call,
            b,
            b.xfrm
                .delete_policy(&backend::policy_id(id)?, &backend::policy_config(config)?,),
            |c: &mut dyn Call_RemovePolicy, ()| c.reply()
        )
    }
    fn query_policy(&self, call: &mut dyn Call_QueryPolicy, id: PolicyId) -> varlink::Result<()> {
        request!(
            self,
            call,
            b,
            b.xfrm.query_policy(&backend::policy_id(id)?),
            |c: &mut dyn Call_QueryPolicy, time: u64| c.reply(time as i64)
        )
    }
    fn flush_policies(&self, call: &mut dyn Call_FlushPolicies) -> varlink::Result<()> {
        request!(
            self,
            call,
            b,
            b.xfrm.flush_policies(),
            |c: &mut dyn Call_FlushPolicies, ()| c.reply()
        )
    }
    fn bypass_port(
        &self,
        call: &mut dyn Call_BypassPort,
        family: i64,
        port: i64,
    ) -> varlink::Result<()> {
        request!(
            self,
            call,
            b,
            {
                let port: u16 = backend::number(port)?;
                let family = backend::number(family)?;
                if port < 1024 {
                    return Err(invalid());
                }
                b.xfrm.port_bypass(family, port)
            },
            |c: &mut dyn Call_BypassPort, ()| c.reply()
        )
    }
    fn get_source_address(
        &self,
        call: &mut dyn Call_GetSourceAddress,
        destination: Endpoint,
        source: Option<Endpoint>,
    ) -> varlink::Result<()> {
        request!(
            self,
            call,
            b,
            {
                let src = source.map(backend::host).transpose()?;
                let (h, _, _) = b
                    .net
                    .lookup(&backend::host(destination)?, src.as_ref(), -1)?;
                Ok(backend::endpoint(h))
            },
            |c: &mut dyn Call_GetSourceAddress, h| c.reply(h)
        )
    }
    fn get_next_hop(
        &self,
        call: &mut dyn Call_GetNextHop,
        destination: Endpoint,
        source: Option<Endpoint>,
        prefix: Option<i64>,
    ) -> varlink::Result<()> {
        request!(
            self,
            call,
            b,
            {
                let dst = backend::host(destination)?;
                let src = source.map(backend::host).transpose()?;
                let prefix: i32 = prefix.map(backend::number).transpose()?.unwrap_or(-1);
                if prefix < -1 || prefix > dst.bits().into() {
                    return Err(invalid());
                }
                let (_, gw, iface) = b.net.lookup(&dst, src.as_ref(), prefix)?;
                Ok((backend::endpoint(gw), iface))
            },
            |c: &mut dyn Call_GetNextHop, (gw, iface)| c.reply(gw, iface)
        )
    }
    fn get_interface(
        &self,
        call: &mut dyn Call_GetInterface,
        address: Endpoint,
    ) -> varlink::Result<()> {
        request!(
            self,
            call,
            b,
            b.net.interface(&backend::host(address)?),
            |c: &mut dyn Call_GetInterface, iface| c.reply(iface)
        )
    }
    fn list_addresses(&self, call: &mut dyn Call_ListAddresses, which: i64) -> varlink::Result<()> {
        request!(
            self,
            call,
            b,
            Ok(b.net
                .enumerate(backend::number(which)?)?
                .into_iter()
                .map(backend::endpoint)
                .collect()),
            |c: &mut dyn Call_ListAddresses, addresses| c.reply(addresses)
        )
    }
    fn list_subnets(&self, call: &mut dyn Call_ListSubnets) -> varlink::Result<()> {
        request!(
            self,
            call,
            b,
            Ok(b.net
                .subnets()?
                .into_iter()
                .map(|(a, p, i)| Subnet {
                    address: backend::endpoint(a),
                    prefix: p.into(),
                    interface: i
                })
                .collect()),
            |c: &mut dyn Call_ListSubnets, subnets| c.reply(subnets)
        )
    }
}
