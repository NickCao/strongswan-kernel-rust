// SPDX-License-Identifier: GPL-2.0-or-later
use crate::{ffi, host, log, status_t_FAILED, status_t_NOT_SUPPORTED, Result};
use kernel_rust_protocol::{
    self as api,
    transport::{peer, Frames, MAX_FRAME},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    ffi::CString,
    io::{self, Write},
    net::Shutdown,
    os::{fd::AsRawFd, unix::net::UnixStream},
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use zeroize::Zeroizing;

pub const REGISTRY: &std::ffi::CStr = c"kernel-rust-client";

#[derive(Serialize, Deserialize)]
pub struct Empty {}

#[derive(Serialize)]
struct Request<'a, P> {
    method: String,
    parameters: &'a P,
    #[serde(skip_serializing_if = "Option::is_none")]
    more: Option<bool>,
}

#[derive(Deserialize)]
struct Reply<T> {
    parameters: Option<T>,
    error: Option<String>,
    continues: Option<bool>,
}

struct Channel {
    stream: UnixStream,
    frames: Frames,
}
impl Channel {
    fn connect(path: &str, uid: u32) -> io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        if peer(&stream)?.uid != uid {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        Ok(Self {
            stream,
            frames: Frames::default(),
        })
    }
    fn send<P: Serialize>(&mut self, method: &str, parameters: &P, more: bool) -> io::Result<()> {
        // Serialize borrowed typed messages directly, avoiding a JSON value copy
        // of SA key strings. Capacity is fixed for all supported requests.
        let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_FRAME));
        serde_json::to_writer(
            &mut *bytes,
            &Request {
                method: format!("io.ranet.Kernel.{method}"),
                parameters,
                more: more.then_some(true),
            },
        )
        .map_err(io::Error::other)?;
        bytes.push(0);
        if bytes.len() > MAX_FRAME {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // UnixStream::write uses MSG_NOSIGNAL on Linux.
        self.stream.write_all(&bytes)
    }
    fn receive<T: DeserializeOwned>(&mut self, flags: i32) -> io::Result<Reply<T>> {
        let frame = self.frames.read_flags(&self.stream, flags)?;
        serde_json::from_slice(&frame[..frame.len() - 1]).map_err(io::Error::other)
    }
}

struct Control {
    channel: Channel,
    failed: bool,
}
pub struct Client {
    control: Mutex<Control>,
    events: Mutex<Channel>,
    closing: AtomicBool,
    pub features: ffi::kernel_feature_t,
}
impl Client {
    pub unsafe fn create() -> Result<Arc<Self>> {
        let (path, uid, parameters) = unsafe {
            let default = CString::new(env!("KERNEL_RUST_SOCKET")).map_err(|_| status_t_FAILED)?;
            (
                host::setting_str(c"%s.plugins.kernel-rust.socket", &default)?,
                host::setting_int(c"%s.plugins.kernel-rust.daemon_uid", 0) as u32,
                api::OpenSession_Args {
                    interfacesUse: host::setting_str(c"%s.interfaces_use", c"")?,
                    interfacesIgnore: host::setting_str(c"%s.interfaces_ignore", c"")?,
                },
            )
        };
        let setup = || -> io::Result<_> {
            let mut control = Channel::connect(&path, uid)?;
            control.send("OpenSession", &parameters, false)?;
            let reply: Reply<api::OpenSession_Reply> = control.receive(0)?;
            let session = if reply.error.is_none() && reply.continues != Some(true) {
                reply.parameters
            } else {
                None
            }
            .ok_or(io::ErrorKind::PermissionDenied)?;
            if session.token.len() != 64 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let features =
                ffi::kernel_feature_t::try_from(session.features).map_err(io::Error::other)?;
            // A setup failure after OpenSession still tries the normal close.
            let events = (|| -> io::Result<_> {
                let mut events = Channel::connect(&path, uid)?;
                events.send(
                    "WatchEvents",
                    &api::WatchEvents_Args {
                        token: session.token,
                    },
                    true,
                )?;
                let ready: Reply<api::WatchEvents_Reply> = events.receive(0)?;
                if ready.error.is_some()
                    || ready.continues != Some(true)
                    || ready
                        .parameters
                        .is_none_or(|p| p.event.kind != api::Event_kind::ready)
                {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                Ok(events)
            })();
            match events {
                Ok(events) => Ok((control, events, features)),
                Err(e) => {
                    let _ = control.send("CloseSession", &Empty {}, false);
                    let _ = control.receive::<Empty>(0);
                    Err(e)
                }
            }
        };
        let (control, events, features) = setup().map_err(|e| {
            log(&format!("connecting to {path} failed: {e}"));
            status_t_FAILED
        })?;
        let fd = events.stream.as_raw_fd();
        let client = Arc::new(Self {
            control: Mutex::new(Control {
                channel: control,
                failed: false,
            }),
            events: Mutex::new(events),
            closing: AtomicBool::new(false),
            features,
        });
        unsafe {
            let watcher = (*ffi::lib).watcher;
            (*watcher).add.unwrap()(
                watcher,
                fd,
                ffi::watcher_event_t_WATCHER_READ,
                Some(receive_events),
                Arc::as_ptr(&client).cast_mut().cast(),
            );
        }
        Ok(client)
    }

    pub fn call<P: Serialize, T: DeserializeOwned>(
        &self,
        method: &str,
        parameters: &P,
    ) -> Result<T> {
        let mut control = self.control.lock().unwrap();
        if control.failed {
            return Err(status_t_FAILED);
        }
        let reply = control
            .channel
            .send(method, parameters, false)
            .and_then(|()| control.channel.receive::<serde_json::Value>(0));
        match reply {
            Ok(reply) if reply.continues != Some(true) => {
                if let Some(error) = reply.error {
                    let errno = reply
                        .parameters
                        .as_ref()
                        .and_then(|v| v.get("errno"))
                        .and_then(|v| v.as_i64());
                    // Only error names and errno are logged; never request values.
                    log(&format!("{method} failed: {error} ({errno:?})"));
                    return Err(if error == "io.ranet.Kernel.KernelError" {
                        match errno {
                            Some(n) if n == libc::EEXIST as i64 => ffi::status_t_ALREADY_DONE,
                            Some(n) if n == libc::ENOENT as i64 || n == libc::ESRCH as i64 => {
                                ffi::status_t_NOT_FOUND
                            }
                            Some(n) if n == libc::EOPNOTSUPP as i64 => status_t_NOT_SUPPORTED,
                            _ => status_t_FAILED,
                        }
                    } else {
                        status_t_FAILED
                    });
                }
                serde_json::from_value(reply.parameters.unwrap_or_else(|| serde_json::json!({})))
                    .map_err(|_| status_t_FAILED)
            }
            _ => {
                log("control connection lost");
                control.failed = true;
                let _ = control.channel.stream.shutdown(Shutdown::Both);
                Err(status_t_FAILED)
            }
        }
    }

    pub fn empty<P: Serialize>(&self, method: &str, parameters: &P) -> ffi::status_t {
        self.call::<_, Empty>(method, parameters)
            .map_or_else(|status| status, |_| ffi::status_t_SUCCESS)
    }

    pub unsafe fn from_registry() -> Option<Arc<Self>> {
        unsafe {
            let raw =
                (*ffi::lib).get.unwrap()(ffi::lib, REGISTRY.as_ptr().cast_mut()).cast::<Self>();
            if raw.is_null() {
                None
            } else {
                Arc::increment_strong_count(raw);
                Some(Arc::from_raw(raw))
            }
        }
    }

    pub fn shutdown(&self) {
        // Keep the plugin's owning Arc alive while stopping callbacks. A Drop
        // impl's exclusive borrow would race with their borrowed Client pointer.
        if self.closing.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = self.call::<_, Empty>("CloseSession", &Empty {});
        let fd = self.events.lock().unwrap().stream.as_raw_fd();
        unsafe {
            let watcher = (*ffi::lib).watcher;
            (*watcher).remove.unwrap()(watcher, fd);
        }
        let mut control = self.control.lock().unwrap();
        control.failed = true;
        let _ = control.channel.stream.shutdown(Shutdown::Both);
        let _ = self.events.lock().unwrap().stream.shutdown(Shutdown::Both);
    }
}

unsafe extern "C" fn receive_events(
    data: *mut libc::c_void,
    _fd: i32,
    _event: ffi::watcher_event_t,
) -> bool {
    // Registered pointer is stable inside Arc; plugin destruction synchronizes
    // watcher removal before releasing its owning reference.
    let client = unsafe { &*data.cast::<Client>() };
    let mut events = client.events.lock().unwrap();
    loop {
        match events.receive::<api::WatchEvents_Reply>(libc::MSG_DONTWAIT) {
            Ok(reply) if reply.continues == Some(true) && reply.error.is_none() => {
                if let Some(parameters) = reply.parameters {
                    dispatch(parameters.event);
                } else {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return true,
            _ => break,
        }
    }
    if !client.closing.load(Ordering::Acquire) {
        log("event connection lost");
        let control = client.control.lock().unwrap();
        let _ = control.channel.stream.shutdown(Shutdown::Both);
    }
    false
}

fn dispatch(event: api::Event) {
    // The watcher runs callbacks on charon's workers. Host arguments are borrowed
    // for the event call; RAII frees them after the host clones what it needs.
    unsafe {
        let kernel = (*ffi::charon).kernel;
        match event.kind {
            api::Event_kind::expire => {
                if let Some(e) = event.expiry {
                    if let (Ok(dst), Ok(protocol), Ok(spi)) = (
                        host::Host::parse(&e.destination),
                        u8::try_from(e.protocol),
                        u32::try_from(e.spi),
                    ) {
                        (*kernel).expire.unwrap()(kernel, protocol, spi.to_be(), dst.0, e.hard);
                    }
                }
            }
            api::Event_kind::mapping => {
                if let Some(e) = event.mapping {
                    if let (Ok(dst), Ok(remote), Ok(spi)) = (
                        host::Host::parse(&e.destination),
                        host::Host::parse(&e.remote),
                        u32::try_from(e.spi),
                    ) {
                        (*kernel).mapping.unwrap()(
                            kernel,
                            libc::IPPROTO_ESP as u8,
                            spi.to_be(),
                            dst.0,
                            remote.0,
                        );
                    }
                }
            }
            api::Event_kind::acquire => {
                if let Some(e) = event.acquire {
                    if let (Ok(src), Ok(dst), Ok(reqid), Ok(seq)) = (
                        host::Selector::parse(&e.src),
                        host::Selector::parse(&e.dst),
                        u32::try_from(e.reqid),
                        u32::try_from(e.sequence),
                    ) {
                        let mut data = ffi::kernel_acquire_data_t {
                            src: src.0,
                            dst: dst.0,
                            label: ptr::null_mut(),
                            cpu: ffi::CPU_ID_MAX,
                            seq,
                        };
                        (*kernel).acquire.unwrap()(kernel, reqid, &mut data);
                    }
                }
            }
            api::Event_kind::roam => {
                if let Some(address) = event.addressChanged {
                    (*kernel).roam.unwrap()(kernel, address);
                }
            }
            api::Event_kind::ready => {}
        }
    }
}
