// SPDX-License-Identifier: GPL-2.0-or-later
use kernel_rust_protocol::notification::Notification;
use rustix::{
    event::{poll, PollFd, PollFlags, Timespec},
    io::{fcntl_getfd, FdFlags},
    net::{sendmsg, SendAncillaryBuffer, SendAncillaryMessage, SendFlags},
};
use std::{
    io::{self, IoSlice, Read, Write},
    mem::MaybeUninit,
    os::{fd::AsFd, unix::net::UnixStream},
};

fn readable(notification: &Notification) -> bool {
    poll(
        &mut [PollFd::new(notification, PollFlags::IN)],
        Some(&Timespec::default()),
    )
    .unwrap()
        != 0
}
#[test]
fn descriptor_handoff_coalesces_wakeups_without_touching_rpc_bytes() {
    let (mut server, mut client) = UnixStream::pair().unwrap();
    let sender = Notification::new().unwrap();
    sender.send(&server).unwrap();
    sender.notify().unwrap(); // A wakeup before the host registers must survive.
    server.write_all(b"tarpc bytes").unwrap();
    let receiver = Notification::receive(&client).unwrap();
    assert!(fcntl_getfd(&receiver).unwrap().contains(FdFlags::CLOEXEC));
    assert!(readable(&receiver));
    assert!(receiver.drain().unwrap());
    assert!(
        !receiver.drain().unwrap(),
        "empty eventfd reads must not block"
    );
    let mut bytes = [0u8; 11];
    client.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"tarpc bytes");
    sender.notify().unwrap();
    sender.notify().unwrap();
    assert!(readable(&receiver));
    assert!(receiver.drain().unwrap());
    assert!(!readable(&receiver));
    assert!(!receiver.drain().unwrap());
    sender.notify().unwrap();
    assert!(
        readable(&receiver),
        "notification after clearing must wake again"
    );
    assert!(receiver.drain().unwrap());
    drop(sender);
    assert!(
        !readable(&receiver),
        "closing the sender does not signal an eventfd"
    );
}
#[test]
fn a_full_counter_is_already_a_pending_notification() {
    let notification = Notification::new().unwrap();
    rustix::io::write(&notification, &(u64::MAX - 1).to_ne_bytes()).unwrap();
    notification.notify().unwrap();
    assert!(readable(&notification));
    assert!(notification.drain().unwrap());
    assert!(!readable(&notification));
}
#[test]
fn missing_or_truncated_descriptor_handoffs_are_rejected() {
    let (mut server, client) = UnixStream::pair().unwrap();
    server.write_all(&[0]).unwrap();
    assert!(
        matches!(Notification::receive(&client), Err(error) if error.kind() == io::ErrorKind::InvalidData)
    );
    drop(server);
    assert!(
        matches!(Notification::receive(&client), Err(error) if error.kind() == io::ErrorKind::UnexpectedEof)
    );

    let (server, client) = UnixStream::pair().unwrap();
    let notification = Notification::new().unwrap();
    let descriptors = [notification.as_fd(); 4];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(4))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    assert!(control.push(SendAncillaryMessage::ScmRights(&descriptors)));
    sendmsg(
        &server,
        &[IoSlice::new(&[0])],
        &mut control,
        SendFlags::NOSIGNAL,
    )
    .unwrap();
    assert!(
        matches!(Notification::receive(&client), Err(error) if error.kind() == io::ErrorKind::InvalidData)
    );
}
