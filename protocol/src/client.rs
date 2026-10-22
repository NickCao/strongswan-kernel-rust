// SPDX-License-Identifier: GPL-2.0-or-later
//! Blocking RPCs driven directly by charon's calling threads.
use crate::{self as api, notification::Notification, transport, KernelClient};
use std::{
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
    pub session: api::SessionConfig,
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("kernel RPC connection is unavailable after an earlier failure")]
    Unavailable,
    #[error(transparent)]
    Remote(#[from] api::Error),
    #[error(transparent)]
    Transport(#[from] RpcError),
}
impl Error {
    pub fn errno(&self) -> Option<i32> {
        match self {
            Self::Remote(api::Error::Kernel(errno)) => Some(*errno),
            _ => None,
        }
    }
}
pub struct Client {
    rpc: KernelClient,
    socket: UnixStream,
    failed: AtomicBool,
    closing: AtomicBool,
    features: api::KernelFeatures,
    notification: Notification,
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
        let notification = Notification::receive(&socket)?;
        socket.set_nonblocking(true)?;
        let control = socket.try_clone()?;
        let (rpc, session) = runtime.block_on(async {
            let socket = tokio::net::UnixStream::from_std(socket)?;
            let rpc =
                KernelClient::new(tarpc::client::Config::default(), transport::framed(socket))
                    .spawn();
            let session = rpc
                .open_session(context::current(), config.session.clone())
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
            notification,
            runtime,
        }))
    }
    pub fn rpc(&self) -> &KernelClient {
        &self.rpc
    }
    pub fn features(&self) -> api::KernelFeatures {
        self.features
    }
    pub fn notification(&self) -> &Notification {
        &self.notification
    }
    pub fn socket(&self) -> &UnixStream {
        &self.socket
    }
    pub fn request<T>(
        &self,
        call: impl Future<Output = Result<api::Result<T>, RpcError>>,
    ) -> Result<T, Error> {
        if self.failed.load(Ordering::Acquire) {
            return Err(Error::Unavailable);
        }
        match self.runtime.block_on(call) {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(Error::Remote(error)),
            Err(error) => {
                self.fail();
                Err(Error::Transport(error))
            }
        }
    }
    /// Drain one event batch. Cancellation stops a pool job during shutdown
    /// without closing the shared connection or canceling other callers.
    pub fn next_events(&self, stop: &CancellationToken) -> Result<Option<Vec<api::Event>>, Error> {
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
