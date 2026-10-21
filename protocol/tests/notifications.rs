// SPDX-License-Identifier: GPL-2.0-or-later
use futures::{SinkExt, StreamExt};
use kernel_rust_protocol::transport::{self, EventSignal, ServerFrame};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::io::AsyncWriteExt;

#[tokio::test(flavor = "current_thread")]
async fn response_read_ahead_wakes_the_host_before_the_notification_is_decoded() {
    let (server, client) = tokio::net::UnixStream::pair().unwrap();
    let mut writer = transport::framed::<(), ServerFrame<u64>>(server);
    // One write contains a reply followed by a push. Reading the reply also
    // removes the push from the kernel socket's readable buffer.
    writer.feed(ServerFrame::Response(42)).await.unwrap();
    writer.feed(ServerFrame::EventsReady).await.unwrap();
    writer.feed(ServerFrame::Response(43)).await.unwrap();
    writer.flush().await.unwrap();
    let signal = Arc::new(EventSignal::default());
    let mut reader = transport::client::<u64, ()>(client, signal.clone());
    assert_eq!(reader.next().await.unwrap().unwrap(), 42);
    assert!(signal.is_pending(), "buffered frames must wake the host");

    // Plugin initialization may install its callback after OpenSession has
    // already read a notification. That notification must remain observable.
    let wakes = Arc::new(AtomicUsize::new(0));
    let observed = wakes.clone();
    signal.set_waker(Some(Arc::new(move || {
        observed.fetch_add(1, Ordering::Relaxed);
    })));
    assert_eq!(wakes.load(Ordering::Relaxed), 1);
    signal.take();
    assert_eq!(reader.next().await.unwrap().unwrap(), 43);
    assert!(
        signal.is_pending(),
        "the push was intercepted before the next reply"
    );

    signal.take();
    drop(writer);
    assert!(reader.next().await.is_none());
    assert!(
        signal.is_pending(),
        "EOF must wake an idle event consumer too"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn empty_frames_are_rejected_instead_of_becoming_heartbeats() {
    let (mut server, client) = tokio::net::UnixStream::pair().unwrap();
    server.write_all(&[0; 4]).await.unwrap();
    let signal = Arc::new(EventSignal::default());
    let mut reader = transport::client::<u64, ()>(client, signal.clone());
    assert_eq!(
        reader.next().await.unwrap().unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    assert!(signal.is_pending());
}
