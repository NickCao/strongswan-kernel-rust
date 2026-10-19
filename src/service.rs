// SPDX-License-Identifier: GPL-2.0-or-later
use crate::{
    backend::{self, Backend},
    error::invalid,
    netlink::Netlink,
    rpc_api::*,
    transport,
};
use std::{
    io::{self, Read},
    os::unix::net::UnixStream,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

pub struct Server {
    pub active: Mutex<Option<Arc<Session>>>,
    pub prefix: String,
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
    control: UnixStream,
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
    pub peer: libc::ucred,
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
fn event_loop(session: Arc<Session>, xfrm: bool, socket: Netlink) {
    while !session.closed.load(Ordering::Acquire) {
        let mut fd = libc::pollfd {
            fd: socket.raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut fd, 1, 200) } <= 0 {
            continue;
        }
        let replies = match socket.receive() {
            Ok(r) => r,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(_) => {
                session.fail();
                break;
            }
        };
        for r in replies {
            let result = if xfrm {
                let mut backend = session.backend.lock().unwrap();
                let result = backend.xfrm.event(&r);
                if let Err(e) = backend.reconcile_interfaces() {
                    eprintln!("kernel-daemon: interface cleanup: {e}");
                }
                result
            } else {
                Ok(Some(Event {
                    kind: Event_kind::roam,
                    addressChanged: Some([16, 17, 20, 21].contains(&r.kind)),
                    expiry: None,
                    acquire: None,
                    mapping: None,
                }))
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
            let backend = Backend::new(
                self.server.prefix.clone(),
                self.server.mtu,
                interfaces_use,
                interfaces_ignore,
            )?;
            let xfrm = Netlink::new(libc::NETLINK_XFRM, 1 | 2 | 128)?;
            let route = Netlink::new(libc::NETLINK_ROUTE, 1 | 0x10 | 0x100 | 0x40 | 0x400)?;
            let mut token = [0u8; 32];
            std::fs::File::open("/dev/urandom")?.read_exact(&mut token)?;
            let token: String = token
                .iter()
                .flat_map(|b| [b >> 4, b & 15])
                .map(|n| char::from(b"0123456789abcdef"[n as usize]))
                .collect();
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
                control: self.socket.try_clone()?,
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
        while s.connected.load(Ordering::Acquire) && !s.closed.load(Ordering::Acquire) {
            match receiver.recv_timeout(Duration::from_millis(200)) {
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
