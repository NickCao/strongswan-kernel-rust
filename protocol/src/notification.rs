// SPDX-License-Identifier: GPL-2.0-or-later
//! Pass a nonblocking eventfd before starting the ordinary tarpc transport.
use rustix::{
    event::{eventfd, EventfdFlags},
    io::{retry_on_intr, Errno},
    net::{
        recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
    },
};
use std::{
    io::{self, IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd},
        unix::net::UnixStream,
    },
    time::Duration,
};

pub struct Notification(OwnedFd);
impl AsRawFd for Notification {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
impl AsFd for Notification {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}
impl Notification {
    pub fn new() -> io::Result<Self> {
        Ok(Self(eventfd(
            0,
            EventfdFlags::NONBLOCK | EventfdFlags::CLOEXEC,
        )?))
    }
    /// Send one descriptor and its required one-byte payload. Both peers must
    /// finish this handshake before registering the socket with Tokio/tarpc.
    pub fn send(&self, socket: &UnixStream) -> io::Result<()> {
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        let descriptors = [self.as_fd()];
        assert!(control.push(SendAncillaryMessage::ScmRights(&descriptors)));
        retry_on_intr(|| {
            sendmsg(
                socket,
                &[IoSlice::new(&[0])],
                &mut control,
                SendFlags::NOSIGNAL,
            )
        })?;
        Ok(())
    }
    pub fn receive(socket: &UnixStream) -> io::Result<Self> {
        // Match the RPC's normal deadline instead of hanging on a silent peer.
        socket.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let mut byte = [0u8];
        let result = retry_on_intr(|| {
            recvmsg(
                socket,
                &mut [IoSliceMut::new(&mut byte)],
                &mut control,
                RecvFlags::CMSG_CLOEXEC,
            )
        })?;
        socket.set_read_timeout(None)?;
        let mut descriptors: Vec<_> = control
            .drain()
            .filter_map(|message| match message {
                RecvAncillaryMessage::ScmRights(fds) => Some(fds),
                _ => None,
            })
            .flatten()
            .collect();
        if result.bytes == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if byte != [0] || result.flags.contains(ReturnFlags::CTRUNC) || descriptors.len() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected one notification eventfd",
            ));
        }
        Ok(Self(descriptors.pop().unwrap()))
    }
    pub fn notify(&self) -> io::Result<()> {
        match retry_on_intr(|| rustix::io::write(self, &1u64.to_ne_bytes())) {
            Ok(_) | Err(Errno::AGAIN) => Ok(()), // A full counter is already readable.
            Err(error) => Err(error.into()),
        }
    }
    /// Clear all coalesced wakeups with one nonblocking read.
    pub fn drain(&self) -> io::Result<bool> {
        match retry_on_intr(|| rustix::io::read(self, &mut [0u8; 8])) {
            Ok(_) => Ok(true),
            Err(Errno::AGAIN) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}
