// SPDX-License-Identifier: GPL-2.0-or-later
//! Blocking RPCs driven directly by charon's calling threads.
use crate::{self as api, transport, KernelClient};
use std::{
    fmt,
    future::Future,
    io,
    net::Shutdown,
    os::unix::net::UnixStream,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tarpc::{client::RpcError, context};
use tokio::runtime::Runtime;
pub use tokio_util::sync::CancellationToken;

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
pub struct Client {
    rpc: KernelClient,
    socket: UnixStream,
    failed: AtomicBool,
    closing: AtomicBool,
    features: u32,
    signal: Arc<transport::EventSignal>,
    // Concurrent block_on calls are supported by Tokio. One caller owns the
    // current-thread scheduler/driver; other callers poll their own RPC futures.
    // Do not serialize whole calls behind a mutex.
    runtime: Runtime,
}
impl Client {
    pub fn connect(config: &Config) -> io::Result<Arc<Self>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let socket = UnixStream::connect(&config.path)?;
        socket.set_nonblocking(true)?;
        let control = socket.try_clone()?;
        let signal = Arc::new(transport::EventSignal::default());
        let (rpc, session) = runtime.block_on(async {
            let socket = tokio::net::UnixStream::from_std(socket)?;
            let rpc = KernelClient::new(
                tarpc::client::Config::default(),
                transport::client(socket, signal.clone()),
            )
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
            Ok::<_, io::Error>((rpc, session))
        })?;
        Ok(Arc::new(Self {
            rpc,
            socket: control,
            failed: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            features: session.features,
            signal,
            runtime,
        }))
    }
    pub fn rpc(&self) -> &KernelClient {
        &self.rpc
    }
    pub fn features(&self) -> u32 {
        self.features
    }
    pub fn event_signal(&self) -> &Arc<transport::EventSignal> {
        &self.signal
    }
    pub fn socket(&self) -> &UnixStream {
        &self.socket
    }
    /// A socket wakeup may have been consumed by another RPC before the pool
    /// job runs. Skip a redundant drain unless transport data remains pending.
    pub fn events_ready(&self) -> io::Result<bool> {
        use rustix::event::{poll, PollFd, PollFlags, Timespec};
        if self.signal.is_pending() {
            return Ok(true);
        }
        let mut ready = [PollFd::new(&self.socket, PollFlags::IN)];
        poll(&mut ready, Some(&Timespec::default()))?;
        Ok(!ready[0].revents().is_empty())
    }
    pub fn request<T>(
        &self,
        call: impl Future<Output = Result<api::Result<T>, RpcError>>,
    ) -> Result<T, Error> {
        if self.failed.load(Ordering::Acquire) {
            return Err(Error {
                errno: None,
                reason: "connection unavailable",
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
                self.fail();
                Err(Error {
                    errno: None,
                    reason: "connection lost",
                })
            }
        }
    }
    /// Drain one event batch. Cancellation stops a pool job during shutdown
    /// without closing the shared connection or canceling other callers.
    pub fn next_events(&self, stop: &CancellationToken) -> Result<Option<Vec<api::Event>>, Error> {
        self.signal.take();
        let result = self.request(async {
            tokio::select! {
                biased;
                _ = stop.cancelled() => Ok(Ok(None)),
                result = self.rpc.next_events(context::current()) => result.map(|batch| batch.map(Some)),
            }
        });
        if result.is_err() {
            self.fail();
        }
        result
    }
    fn fail(&self) {
        self.failed.store(true, Ordering::Release);
        let _ = self.socket.shutdown(Shutdown::Both);
    }
    pub fn close(&self) -> Result<(), Error> {
        if self.closing.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let result = self.request(self.rpc.close_session(context::current()));
        self.fail();
        result
    }
}
