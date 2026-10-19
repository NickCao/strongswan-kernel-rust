// SPDX-License-Identifier: GPL-2.0-or-later
//! Safe Varlink client. No C objects, raw descriptors, callbacks, or host globals.
use crate::{self as api, transport::peer};
use rustix::net::{recv, RecvFlags};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fmt,
    io::{self, Write},
    net::Shutdown,
    os::{
        fd::{AsFd, BorrowedFd},
        unix::net::UnixStream,
    },
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use varlink::sansio::{Client as Protocol, ClientEvent};

pub struct Config {
    pub path: String,
    pub daemon_uid: u32,
    pub interfaces_use: String,
    pub interfaces_ignore: String,
}

#[derive(Debug)]
pub struct Error {
    pub method: String,
    pub errno: Option<i32>,
    reason: &'static str,
}
impl fmt::Display for Error {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            out,
            "{} failed: {} ({:?})",
            self.method, self.reason, self.errno
        )
    }
}
impl std::error::Error for Error {}

#[derive(Debug, Serialize, Deserialize)]
pub struct Empty {}

struct Channel {
    stream: UnixStream,
    protocol: Protocol,
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
            protocol: Protocol::new(),
        })
    }
    fn send<P: Serialize>(&mut self, method: &str, parameters: &P, more: bool) -> io::Result<()> {
        let method = format!("io.ranet.Kernel.{method}");
        let mut request = varlink::Request::create(
            method.clone(),
            Some(serde_json::to_value(parameters).map_err(io::Error::other)?),
        );
        request.more = more.then_some(true);
        self.protocol
            .send_request(method, request)
            .map_err(io::Error::other)?;
        while let Some(transmit) = self.protocol.poll_transmit() {
            self.stream.write_all(&transmit.payload)?;
        }
        Ok(())
    }
    fn receive(&mut self, flags: RecvFlags) -> io::Result<varlink::Reply> {
        loop {
            match self.protocol.poll_event() {
                Some(ClientEvent::Reply { reply, .. }) => return Ok(reply),
                Some(_) => return Err(io::ErrorKind::InvalidData.into()),
                None => (),
            }
            let mut bytes = [0u8; 4096];
            match recv(&self.stream, &mut bytes[..], flags) {
                Ok((0, _)) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok((length, _)) => self
                    .protocol
                    .handle_input(&bytes[..length])
                    .map_err(io::Error::other)?,
                Err(rustix::io::Errno::INTR) => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }
}
fn decode_reply<T: DeserializeOwned>(reply: varlink::Reply) -> io::Result<T> {
    serde_json::from_value(reply.parameters.unwrap_or_else(|| serde_json::json!({})))
        .map_err(io::Error::other)
}

struct Control {
    channel: Channel,
    failed: bool,
}
pub struct Client {
    control: Mutex<Control>,
    closing: AtomicBool,
    features: i32,
}
pub struct Events {
    channel: Channel,
}
impl AsFd for Events {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.channel.stream.as_fd()
    }
}
impl Events {
    pub fn next_event(&mut self) -> io::Result<api::Event> {
        let reply = self.channel.receive(RecvFlags::DONTWAIT)?;
        if reply.error.is_some() || reply.continues != Some(true) {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        decode_reply::<api::WatchEvents_Reply>(reply).map(|reply| reply.event)
    }
}

impl Client {
    pub fn connect(config: &Config) -> io::Result<(Arc<Self>, Events)> {
        let mut control = Channel::connect(&config.path, config.daemon_uid)?;
        control.send(
            "OpenSession",
            &api::OpenSession_Args {
                interfacesUse: config.interfaces_use.clone(),
                interfacesIgnore: config.interfaces_ignore.clone(),
            },
            false,
        )?;
        let reply = control.receive(RecvFlags::empty())?;
        let session = if reply.error.is_none() && reply.continues != Some(true) {
            decode_reply::<api::OpenSession_Reply>(reply).ok()
        } else {
            None
        }
        .ok_or(io::ErrorKind::PermissionDenied)?;
        let setup = || -> io::Result<_> {
            if session.token.len() != 64 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let features = i32::try_from(session.features).map_err(io::Error::other)?;
            let mut events = Channel::connect(&config.path, config.daemon_uid)?;
            events.send(
                "WatchEvents",
                &api::WatchEvents_Args {
                    token: session.token,
                },
                true,
            )?;
            let ready = events.receive(RecvFlags::empty())?;
            if ready.error.is_some()
                || ready.continues != Some(true)
                || decode_reply::<api::WatchEvents_Reply>(ready)?.event.kind
                    != api::Event_kind::ready
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Ok((events, features))
        };
        let (events, features) = match setup() {
            Ok(values) => values,
            Err(error) => {
                let _ = control.send("CloseSession", &Empty {}, false);
                let _ = control.receive(RecvFlags::empty());
                return Err(error);
            }
        };
        Ok((
            Arc::new(Self {
                control: Mutex::new(Control {
                    channel: control,
                    failed: false,
                }),
                closing: AtomicBool::new(false),
                features,
            }),
            Events { channel: events },
        ))
    }

    pub fn features(&self) -> i32 {
        self.features
    }

    pub fn request<P: Serialize, T: DeserializeOwned>(
        &self,
        method: &str,
        parameters: &P,
    ) -> Result<T, Error> {
        let error = |reason, errno| Error {
            method: method.to_owned(),
            errno,
            reason,
        };
        let mut control = self.control.lock().unwrap();
        if control.failed {
            return Err(error("control connection unavailable", None));
        }
        let reply = control
            .channel
            .send(method, parameters, false)
            .and_then(|()| control.channel.receive(RecvFlags::empty()));
        match reply {
            Ok(reply) if reply.continues != Some(true) => {
                if let Some(remote) = reply.error {
                    let errno = if remote == "io.ranet.Kernel.KernelError" {
                        reply
                            .parameters
                            .as_ref()
                            .and_then(|v| v.get("errno"))
                            .and_then(|v| v.as_i64())
                            .and_then(|n| i32::try_from(n).ok())
                            .filter(|n| *n > 0)
                    } else {
                        None
                    };
                    return Err(error("remote error", errno));
                }
                decode_reply(reply).map_err(|_| error("invalid reply", None))
            }
            _ => {
                control.failed = true;
                let _ = control.channel.stream.shutdown(Shutdown::Both);
                Err(error("control connection lost", None))
            }
        }
    }

    pub fn event_disconnected(&self) {
        let mut control = self.control.lock().unwrap();
        if !self.closing.load(Ordering::Acquire) {
            control.failed = true;
            let _ = control.channel.stream.shutdown(Shutdown::Both);
        }
    }

    pub fn close(&self) -> Result<(), Error> {
        if self.closing.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let result = self.request::<_, Empty>("CloseSession", &Empty {});
        let mut control = self.control.lock().unwrap();
        control.failed = true;
        let _ = control.channel.stream.shutdown(Shutdown::Both);
        result.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::{
        io::{BufRead, BufReader, Read},
        os::unix::net::UnixListener,
        thread,
    };

    fn fixture() -> (tempfile::TempDir, UnixListener, Config) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("kernel.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (a, _b) = UnixStream::pair().unwrap();
        let config = Config {
            path: path.to_str().unwrap().into(),
            daemon_uid: peer(&a).unwrap().uid,
            interfaces_use: "eth0".into(),
            interfaces_ignore: "lo".into(),
        };
        (directory, listener, config)
    }
    fn request(stream: &mut UnixStream) -> Value {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut frame = Vec::new();
        BufReader::new(stream).read_until(0, &mut frame).unwrap();
        serde_json::from_slice(&frame[..frame.len() - 1]).unwrap()
    }
    fn reply(stream: &mut UnixStream, value: Value) {
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(0);
        stream.write_all(&bytes).unwrap();
    }
    fn handshake(listener: &UnixListener, ready: Value) -> (UnixStream, UnixStream) {
        let (mut control, _) = listener.accept().unwrap();
        let open = request(&mut control);
        assert_eq!(open["method"], "io.ranet.Kernel.OpenSession");
        assert_eq!(open["parameters"]["interfacesUse"], "eth0");
        reply(
            &mut control,
            json!({"parameters":{"token":"a".repeat(64),"features":4}}),
        );
        let (mut events, _) = listener.accept().unwrap();
        let watch = request(&mut events);
        assert_eq!(watch["method"], "io.ranet.Kernel.WatchEvents");
        assert_eq!(watch["parameters"]["token"], "a".repeat(64));
        assert_eq!(watch["more"], true);
        reply(&mut events, ready);
        (control, events)
    }
    fn ready() -> Value {
        json!({"continues":true,"parameters":{"event":{"kind":"ready"}}})
    }

    #[test]
    fn typed_rpc_errors_and_clean_close_over_unix_streams() {
        let (_directory, listener, config) = fixture();
        let server = thread::spawn(move || {
            let (mut control, mut events) = handshake(&listener, ready());
            assert_eq!(request(&mut control)["method"], "io.ranet.Kernel.InstallSa");
            reply(
                &mut control,
                json!({"error":"io.ranet.Kernel.KernelError","parameters":{"errno":libc::EEXIST}}),
            );
            assert_eq!(request(&mut control)["method"], "io.ranet.Kernel.QuerySa");
            reply(
                &mut control,
                json!({"parameters":{"bytes":u64::MAX.to_string(),"packets":"42","lastUse":7}}),
            );
            assert_eq!(
                request(&mut control)["method"],
                "io.ranet.Kernel.CloseSession"
            );
            // A Varlink method with no output may omit parameters altogether.
            reply(&mut control, json!({}));
            let mut bytes = [0u8];
            assert_eq!(control.read(&mut bytes).unwrap(), 0);
            // The client owns its event connection until the registration drops.
            assert_eq!(events.read(&mut bytes).unwrap(), 0);
        });
        let (client, events) = Client::connect(&config).unwrap();
        assert_eq!(client.features(), 4);
        let error = client
            .request::<_, Empty>("InstallSa", &Empty {})
            .unwrap_err();
        assert_eq!(error.errno, Some(libc::EEXIST));
        let counters: api::QuerySa_Reply = client.request("QuerySa", &Empty {}).unwrap();
        assert_eq!(counters.bytes, u64::MAX.to_string());
        assert_eq!(counters.packets, "42");
        client.close().unwrap();
        // Closing is idempotent and does not send another mutation.
        client.close().unwrap();
        drop(events);
        server.join().unwrap();
    }

    #[test]
    fn event_channel_loss_disables_control_without_replaying() {
        let (_directory, listener, config) = fixture();
        let server = thread::spawn(move || {
            let (mut control, events) = handshake(&listener, ready());
            drop(events);
            control
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut bytes = [0u8];
            assert_eq!(control.read(&mut bytes).unwrap(), 0);
        });
        let (client, mut events) = Client::connect(&config).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match events.next_event() {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "event stream did not disconnect"
                    );
                    thread::yield_now()
                }
                Err(_) => break,
                Ok(_) => panic!("unexpected event"),
            }
        }
        client.event_disconnected();
        assert!(client.request::<_, Empty>("InstallSa", &Empty {}).is_err());
        assert!(client.close().is_err());
        server.join().unwrap();
    }

    #[test]
    fn rejected_event_handshake_releases_empty_session() {
        let (_directory, listener, config) = fixture();
        let server = thread::spawn(move || {
            let (mut control, _events) =
                handshake(&listener, json!({"error":"io.ranet.Kernel.InvalidSession"}));
            assert_eq!(
                request(&mut control)["method"],
                "io.ranet.Kernel.CloseSession"
            );
            reply(&mut control, json!({}));
        });
        assert!(Client::connect(&config).is_err());
        server.join().unwrap();
    }

    #[test]
    fn wrong_daemon_uid_is_rejected_before_sending_session_data() {
        let (_directory, listener, mut config) = fixture();
        config.daemon_uid = config.daemon_uid.wrapping_add(1);
        let server = thread::spawn(move || {
            let (mut control, _) = listener.accept().unwrap();
            let mut bytes = [0u8];
            assert_eq!(control.read(&mut bytes).unwrap(), 0);
        });
        assert!(
            matches!(Client::connect(&config), Err(error) if error.kind() == io::ErrorKind::PermissionDenied)
        );
        server.join().unwrap();
    }

    #[test]
    fn nonblocking_events_keep_fragmented_and_coalesced_replies() {
        let (_directory, listener, config) = fixture();
        let (sent, received) = std::sync::mpsc::channel();
        let (advance, next) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let (mut control, mut events) = handshake(&listener, ready());
            let bytes = serde_json::to_vec(&json!({"continues":true,
                "parameters":{"event":{"kind":"roam","addressChanged":true}}}))
            .unwrap();
            let split = bytes.len() / 2;
            events.write_all(&bytes[..split]).unwrap();
            sent.send(()).unwrap();
            next.recv().unwrap();
            events.write_all(&bytes[split..]).unwrap();
            events.write_all(b"\0").unwrap();
            reply(
                &mut events,
                json!({"continues":true,
                "parameters":{"event":{"kind":"roam","addressChanged":false}}}),
            );
            events.write_all(&bytes[..split]).unwrap();
            sent.send(()).unwrap();
            next.recv().unwrap();
            events.write_all(&bytes[split..]).unwrap();
            events.write_all(b"\0").unwrap();
            sent.send(()).unwrap();
            assert_eq!(
                request(&mut control)["method"],
                "io.ranet.Kernel.CloseSession"
            );
            reply(&mut control, json!({}));
        });
        let (client, mut events) = Client::connect(&config).unwrap();
        received.recv().unwrap();
        assert_eq!(
            events.next_event().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        advance.send(()).unwrap();
        received.recv().unwrap();
        assert_eq!(events.next_event().unwrap().addressChanged, Some(true));
        assert_eq!(events.next_event().unwrap().addressChanged, Some(false));
        assert_eq!(
            events.next_event().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        advance.send(()).unwrap();
        received.recv().unwrap();
        assert_eq!(events.next_event().unwrap().addressChanged, Some(true));
        client.close().unwrap();
        server.join().unwrap();
    }
}
