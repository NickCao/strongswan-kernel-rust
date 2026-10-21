// SPDX-License-Identifier: GPL-2.0-or-later
//! Typed server notifications multiplexed with tarpc replies on one socket.
use futures::{ready, Sink, SinkExt, Stream, StreamExt, TryStreamExt};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
};

/// A coalesced wakeup, also usable before the host installs its callback.
#[derive(Default)]
pub struct EventSignal {
    pending: AtomicBool,
    notified: tokio::sync::Notify,
    wake: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}
impl EventSignal {
    pub fn notify(&self) {
        self.pending.store(true, Ordering::Release);
        self.notified.notify_one();
        self.wake();
    }
    pub fn wake(&self) {
        let wake = self.wake.lock().unwrap().clone();
        if let Some(wake) = wake {
            wake();
        }
    }
    pub fn is_pending(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }
    pub fn take(&self) -> bool {
        self.pending.swap(false, Ordering::AcqRel)
    }
    pub async fn notified(&self) {
        self.notified.notified().await;
    }
    pub fn set_waker(&self, wake: Option<Arc<dyn Fn() + Send + Sync>>) {
        *self.wake.lock().unwrap() = wake.clone();
        if self.is_pending() {
            if let Some(wake) = wake {
                wake();
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum ServerFrame<T> {
    Response(T),
    EventsReady,
}

pub type Framed<In, Out> = tarpc::tokio_serde::Framed<
    tarpc::tokio_util::codec::Framed<
        tokio::net::UnixStream,
        tarpc::tokio_util::codec::length_delimited::LengthDelimitedCodec,
    >,
    In,
    Out,
    tarpc::tokio_serde::formats::Bincode<In, Out>,
>;

pub fn framed<In: serde::de::DeserializeOwned, Out: serde::Serialize>(
    socket: tokio::net::UnixStream,
) -> Framed<In, Out> {
    let codec = tarpc::tokio_util::codec::length_delimited::LengthDelimitedCodec::builder()
        .max_frame_length(8 * 1024 * 1024)
        .new_framed(socket);
    tarpc::tokio_serde::Framed::new(codec, tarpc::tokio_serde::formats::Bincode::default())
}

pub struct ClientTransport<In, Out> {
    inner: Framed<ServerFrame<In>, Out>,
    signal: Arc<EventSignal>,
}
pub fn client<In: DeserializeOwned, Out: Serialize>(
    socket: tokio::net::UnixStream,
    signal: Arc<EventSignal>,
) -> ClientTransport<In, Out> {
    ClientTransport {
        inner: framed(socket),
        signal,
    }
}
impl<In: DeserializeOwned + Unpin, Out: Serialize + Unpin> Stream for ClientTransport<In, Out> {
    type Item = io::Result<In>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match ready!(Pin::new(&mut self.inner).poll_next(cx)) {
                Some(Ok(ServerFrame::EventsReady)) => self.signal.notify(),
                Some(Ok(ServerFrame::Response(response))) => {
                    // A response may be followed by a notification already
                    // read into Framed's buffer. The socket alone can no
                    // longer wake the host for that data.
                    if !self.inner.get_ref().read_buffer().is_empty() {
                        self.signal.notify();
                    }
                    return Poll::Ready(Some(Ok(response)));
                }
                Some(Err(error)) => {
                    self.signal.notify();
                    return Poll::Ready(Some(Err(error)));
                }
                None => {
                    self.signal.notify();
                    return Poll::Ready(None);
                }
            }
        }
    }
}
impl<In: DeserializeOwned + Unpin, Out: Serialize + Unpin> Sink<Out> for ClientTransport<In, Out> {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_ready(cx)
    }
    fn start_send(mut self: Pin<&mut Self>, message: Out) -> io::Result<()> {
        Pin::new(&mut self.inner).start_send(message)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

pub type ServerTransport<Req, Resp> =
    tarpc::transport::channel::Channel<tarpc::ClientMessage<Req>, tarpc::Response<Resp>>;

/// Read and write independently: backpressure on notifications must not stop
/// requests or cancellation from reaching tarpc. Dropping the driver closes
/// both directions, so connection teardown also terminates the channel.
pub fn server<Req, Resp>(
    socket: tokio::net::UnixStream,
    notifications: impl Stream<Item = ()> + Send + 'static,
) -> (
    ServerTransport<Req, Resp>,
    impl Future<Output = io::Result<()>>,
)
where
    Req: DeserializeOwned + Send + Unpin + 'static,
    Resp: Serialize + Send + Unpin + 'static,
{
    let (server, bridge) = tarpc::transport::channel::bounded(16);
    let (requests, responses) = bridge.split();
    let (writer, reader) = framed(socket).split();
    let receive = reader.forward(requests.sink_map_err(io::Error::other));
    let notifications = notifications.map(|()| Ok(ServerFrame::EventsReady));
    let replies = responses
        .map_err(io::Error::other)
        .map_ok(ServerFrame::Response);
    let send = futures::stream::select(replies, notifications.boxed()).forward(writer);
    let drive = async move {
        tokio::select! {
            result = receive => result,
            result = send => result,
        }
    };
    (server, drive)
}
