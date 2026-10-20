// SPDX-License-Identifier: GPL-2.0-or-later
//! Blocking bridge for charon's synchronous callbacks. tarpc owns wire framing,
//! typed dispatch and async I/O; a local socket pair only wakes charon's watcher.
use crate::{self as api, transport, KernelClient};
use std::{
    collections::VecDeque,
    fmt,
    future::Future,
    io::{self, Read, Write},
    net::Shutdown,
    os::{
        fd::{AsFd, BorrowedFd},
        unix::net::UnixStream,
    },
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::Duration,
};
use tarpc::{client::RpcError, context};
use tokio::{runtime::Runtime, task::JoinHandle};

pub struct Config {
    pub path: String,
    pub interfaces_use: String,
    pub interfaces_ignore: String,
}
#[derive(Debug)]
pub struct Error {
    pub errno: Option<i32>,
    reason: &'static str,
}
impl fmt::Display for Error {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "{} ({:?})", self.reason, self.errno)
    }
}
impl std::error::Error for Error {}
struct State {
    failed: AtomicBool,
    closing: AtomicBool,
    control: UnixStream,
}
impl State {
    fn fail(&self) {
        if !self.closing.load(Ordering::Acquire) {
            self.failed.store(true, Ordering::Release);
            let _ = self.control.shutdown(Shutdown::Both);
        }
    }
}
pub struct Client {
    rpc: KernelClient,
    state: Arc<State>,
    features: u32,
    // Keep the runtime alive until the client channels and their tasks drop.
    runtime: Runtime,
}
pub struct Events {
    wakeup: UnixStream,
    receiver: mpsc::Receiver<io::Result<Vec<api::Event>>>,
    pending: VecDeque<api::Event>,
    task: JoinHandle<()>,
}
impl AsFd for Events {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.wakeup.as_fd()
    }
}
impl Events {
    pub fn next_event(&mut self) -> io::Result<api::Event> {
        loop {
            if let Some(event) = self.pending.pop_front() {
                return Ok(event);
            }
            // Drain readiness even if the queue is empty: a producer may have
            // written its wakeup after the consumer already took that batch.
            let mut signal = [0u8; 256];
            let _ = self.wakeup.read(&mut signal);
            match self.receiver.try_recv() {
                Ok(batch) => {
                    self.pending.extend(batch?);
                }
                Err(mpsc::TryRecvError::Empty) => return Err(io::ErrorKind::WouldBlock.into()),
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err(io::ErrorKind::ConnectionAborted.into());
                }
            }
        }
    }
}
impl Drop for Events {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn connect(path: &str) -> io::Result<KernelClient> {
    let socket = tokio::net::UnixStream::connect(path).await?;
    Ok(KernelClient::new(tarpc::client::Config::default(), transport::framed(socket)).spawn())
}

impl Client {
    pub fn connect(config: &Config) -> io::Result<(Arc<Self>, Events)> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("kernel-rpc")
            .enable_all()
            .build()?;
        let socket = UnixStream::connect(&config.path)?;
        socket.set_nonblocking(true)?;
        let control = socket.try_clone()?;
        let (rpc, watch, features) = runtime.block_on(async {
            let socket = tokio::net::UnixStream::from_std(socket)?;
            let rpc =
                KernelClient::new(tarpc::client::Config::default(), transport::framed(socket))
                    .spawn();
            let session = rpc
                .open_session(
                    context::current(),
                    api::SessionConfig {
                        interfaces_use: config.interfaces_use.clone(),
                        interfaces_ignore: config.interfaces_ignore.clone(),
                    },
                )
                .await
                .map_err(io::Error::other)?
                .map_err(io::Error::other)?;
            let attach = async {
                let watch = connect(&config.path).await?;
                watch
                    .subscribe_events(context::current(), session.token)
                    .await
                    .map_err(io::Error::other)?
                    .map_err(io::Error::other)?;
                Ok::<_, io::Error>(watch)
            }
            .await;
            match attach {
                Ok(watch) => Ok((rpc, watch, session.features)),
                Err(error) => {
                    let _ = rpc.close_session(context::current()).await;
                    Err(error)
                }
            }
        })?;
        let state = Arc::new(State {
            failed: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            control,
        });
        let (wakeup, mut signal) = UnixStream::pair()?;
        wakeup.set_nonblocking(true)?;
        signal.set_nonblocking(true)?;
        let (sender, receiver) = mpsc::sync_channel(256);
        let event_state = state.clone();
        let task = runtime.spawn(async move {
            loop {
                // The daemon returns a heartbeat on quiet subscriptions.
                // A missed deadline fails the connection, without replaying calls.
                let mut ctx = context::current();
                ctx.deadline = std::time::Instant::now() + Duration::from_secs(60);
                let batch = match watch.next_events(ctx).await {
                    Ok(Ok(batch)) => Ok(batch),
                    _ => Err(io::Error::from(io::ErrorKind::ConnectionAborted)),
                };
                if batch.as_ref().is_ok_and(Vec::is_empty) {
                    continue;
                }
                let failed = batch.is_err();
                if sender.try_send(batch).is_err() || signal.write_all(&[1]).is_err() || failed {
                    event_state.fail();
                    break;
                }
            }
        });
        Ok((
            Arc::new(Self {
                rpc,
                state,
                features,
                runtime,
            }),
            Events {
                wakeup,
                receiver,
                pending: VecDeque::new(),
                task,
            },
        ))
    }
    pub fn rpc(&self) -> &KernelClient {
        &self.rpc
    }
    pub fn features(&self) -> u32 {
        self.features
    }
    pub fn request<T>(
        &self,
        call: impl Future<Output = std::result::Result<api::Result<T>, RpcError>>,
    ) -> std::result::Result<T, Error> {
        if self.state.failed.load(Ordering::Acquire) {
            return Err(Error {
                errno: None,
                reason: "control connection unavailable",
            });
        }
        match self.runtime.block_on(call) {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(Error {
                errno: if let api::Error::Kernel(errno) = error {
                    Some(errno)
                } else {
                    None
                },
                reason: "remote error",
            }),
            Err(_) => {
                self.state.failed.store(true, Ordering::Release);
                let _ = self.state.control.shutdown(Shutdown::Both);
                Err(Error {
                    errno: None,
                    reason: "control connection lost",
                })
            }
        }
    }
    pub fn event_disconnected(&self) {
        self.state.fail();
    }
    pub fn close(&self) -> std::result::Result<(), Error> {
        if self.state.closing.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let result = self.request(self.rpc.close_session(context::current()));
        self.state.failed.store(true, Ordering::Release);
        let _ = self.state.control.shutdown(Shutdown::Both);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wakeup_written_after_its_batch_was_consumed_is_drained() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let (wakeup, mut signal) = UnixStream::pair().unwrap();
        wakeup.set_nonblocking(true).unwrap();
        let (sender, receiver) = mpsc::sync_channel(1);
        let mut events = Events {
            wakeup,
            receiver,
            pending: VecDeque::new(),
            task: runtime.spawn(async {}),
        };
        sender
            .send(Ok(vec![api::Event {
                kind: api::EventKind::Roam,
                address_changed: Some(true),
                expiry: None,
                acquire: None,
                mapping: None,
            }]))
            .unwrap();
        events.next_event().unwrap();
        // Deliberately publish the wakeup after the consumer took the data.
        signal.write_all(&[1]).unwrap();
        assert_eq!(
            events.next_event().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let mut descriptors = [rustix::event::PollFd::new(
            &events,
            rustix::event::PollFlags::IN,
        )];
        assert_eq!(
            rustix::event::poll(
                &mut descriptors,
                Some(&rustix::time::Timespec {
                    tv_sec: 0,
                    tv_nsec: 0
                })
            )
            .unwrap(),
            0
        );
    }
}
