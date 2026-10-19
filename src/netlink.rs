// SPDX-License-Identifier: GPL-2.0-or-later
use crate::{error::invalid, uapi::*};
use rustix::{
    fd::{AsFd, BorrowedFd, OwnedFd},
    net::{
        self, netlink::SocketAddrNetlink, sockopt, AddressFamily, Protocol, RecvFlags, SendFlags,
        SocketFlags, SocketType,
    },
};
use std::{io, time::Duration};
use zeroize::Zeroizing;

pub const REQUEST: u16 = 1;
pub const ACK: u16 = 4;
pub const DUMP: u16 = 0x300;
pub const CREATE: u16 = 0x400;
pub const EXCL: u16 = 0x200;
pub const REPLACE: u16 = 0x100;
pub const APPEND: u16 = 0x800;
pub fn align(n: usize) -> usize {
    (n + 3) & !3
}

pub struct Message {
    pub kind: u16,
    pub flags: u16,
    pub payload: Zeroizing<Vec<u8>>,
}
impl Message {
    pub fn new(kind: u16, flags: u16, payload: Vec<u8>) -> Self {
        Self {
            kind,
            flags: flags | REQUEST,
            payload: Zeroizing::new(payload),
        }
    }
    pub fn attr(&mut self, kind: u16, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > u16::MAX as usize - 4 || self.payload.len() + bytes.len() > 1024 * 1024 {
            return Err(invalid());
        }
        let required = align(self.payload.len()) + align(bytes.len() + 4);
        if required > self.payload.capacity() {
            // Vec::reserve() can free an allocation without wiping it. Once
            // an algorithm attribute has been appended it contains SA keys,
            // so explicitly replace and wipe the old allocation on growth.
            let mut replacement = Zeroizing::new(Vec::with_capacity(required.next_power_of_two()));
            replacement.extend_from_slice(&self.payload);
            std::mem::swap(&mut self.payload, &mut replacement);
        }
        let padded = align(self.payload.len());
        self.payload.resize(padded, 0);
        self.payload
            .extend_from_slice(&((bytes.len() + 4) as u16).to_ne_bytes());
        self.payload.extend_from_slice(&kind.to_ne_bytes());
        self.payload.extend_from_slice(bytes);
        let padded = align(self.payload.len());
        self.payload.resize(padded, 0);
        Ok(())
    }
    pub fn attr32(&mut self, kind: u16, v: u32) -> io::Result<()> {
        self.attr(kind, &v.to_ne_bytes())
    }
    pub fn encode(&self, seq: u32) -> Zeroizing<Vec<u8>> {
        let mut b = Zeroizing::new(vec![0; 16]);
        put32(&mut b, 0, (16 + self.payload.len()) as u32);
        put16(&mut b, 4, self.kind);
        put16(&mut b, 6, self.flags);
        put32(&mut b, 8, seq);
        b.extend_from_slice(&self.payload);
        b
    }
}

pub fn attrs(mut data: &[u8]) -> io::Result<Vec<(u16, &[u8])>> {
    let mut result = Vec::new();
    while !data.is_empty() {
        if data.len() < 4 {
            return Err(invalid());
        }
        let len = get16(data, 0) as usize;
        if len < 4 || len > data.len() {
            return Err(invalid());
        }
        result.push((get16(data, 2) & 0x3fff, &data[4..len]));
        if len == data.len() {
            break;
        }
        if align(len) > data.len() {
            return Err(invalid());
        }
        data = &data[align(len)..];
    }
    Ok(result)
}
pub struct Reply {
    pub kind: u16,
    pub flags: u16,
    pub seq: u32,
    pub payload: Zeroizing<Vec<u8>>,
}
pub fn messages(mut data: &[u8]) -> io::Result<Vec<Reply>> {
    let mut out = Vec::new();
    while !data.is_empty() {
        if data.len() < 16 {
            return Err(invalid());
        }
        let len = get32(data, 0) as usize;
        if len < 16 || len > data.len() {
            return Err(invalid());
        }
        out.push(Reply {
            kind: get16(data, 4),
            flags: get16(data, 6),
            seq: get32(data, 8),
            payload: Zeroizing::new(data[16..len].to_vec()),
        });
        if len == data.len() {
            break;
        }
        if align(len) > data.len() {
            return Err(invalid());
        }
        data = &data[align(len)..];
    }
    Ok(out)
}

pub struct Netlink {
    fd: OwnedFd,
    seq: u32,
}
impl Netlink {
    pub fn new(protocol: i32, groups: u32) -> io::Result<Self> {
        let fd = net::socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::CLOEXEC,
            std::num::NonZeroU32::new(protocol as u32).map(Protocol::from_raw),
        )?;
        net::bind(&fd, &SocketAddrNetlink::new(0, groups))?;
        let _ = sockopt::set_socket_recv_buffer_size(&fd, 4 * 1024 * 1024);
        sockopt::set_socket_timeout(&fd, sockopt::Timeout::Recv, Some(Duration::from_secs(5)))?;
        Ok(Self { fd, seq: 0 })
    }
    pub fn receive(&self) -> io::Result<Vec<Reply>> {
        // The second return value is the full datagram length with MSG_TRUNC,
        // not the number of bytes copied into the one-byte peek buffer.
        let mut one = [0u8];
        let len = loop {
            match net::recv(&self.fd, &mut one[..], RecvFlags::PEEK | RecvFlags::TRUNC) {
                Ok((_, len)) => break len,
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => return Err(e.into()),
            }
        };
        if len == 0 || len > 4 * 1024 * 1024 {
            return Err(invalid());
        }
        let mut bytes = Zeroizing::new(vec![0; len]);
        let (copied, received, sender) =
            net::recvfrom(&self.fd, &mut bytes[..], RecvFlags::empty())?;
        let sender = sender.ok_or_else(invalid)?;
        let sender = SocketAddrNetlink::try_from(sender)?;
        if sender.pid() != 0 {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        if copied != len || received != len {
            return Err(invalid());
        }
        messages(&bytes)
    }
    pub fn request(&mut self, msg: &Message) -> io::Result<Vec<Reply>> {
        self.seq = self.seq.wrapping_add(1).max(1);
        let seq = self.seq;
        let bytes = msg.encode(seq);
        let dest = SocketAddrNetlink::new(0, 0);
        loop {
            match net::sendto(&self.fd, &bytes, SendFlags::empty(), &dest) {
                Ok(n) if n == bytes.len() => break,
                Ok(_) => return Err(invalid()),
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        let mut result = Vec::new();
        loop {
            let mut done = false;
            for r in self.receive()? {
                if r.seq != seq {
                    continue;
                }
                if r.flags & 0x10 != 0 {
                    return Err(io::Error::from_raw_os_error(libc::EINTR));
                } // DUMP_INTR
                match r.kind {
                    2 => {
                        // NLMSG_ERROR, including a successful ACK
                        if r.payload.len() < 4 {
                            return Err(invalid());
                        }
                        let errno = get32(&r.payload, 0) as i32;
                        if errno != 0 {
                            return Err(io::Error::from_raw_os_error(errno.saturating_neg()));
                        }
                        done = true;
                    }
                    3 => {
                        if r.payload.len() >= 4 && get32(&r.payload, 0) != 0 {
                            return Err(io::Error::from_raw_os_error(
                                (get32(&r.payload, 0) as i32).saturating_neg(),
                            ));
                        }
                        done = true;
                    }
                    4 => return Err(io::Error::from_raw_os_error(libc::ENOBUFS)),
                    _ => {
                        if r.flags & 2 == 0 && msg.flags & ACK == 0 {
                            done = true;
                        }
                        result.push(r);
                    }
                }
            }
            if done {
                return Ok(result);
            }
        }
    }
    pub fn ack(&mut self, msg: &Message) -> io::Result<()> {
        self.request(msg).map(|_| ())
    }
}

impl AsFd for Netlink {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_attributes_and_messages() {
        for bytes in [&[1u8, 0, 1, 0][..], &[8, 0, 1, 0][..], &[4, 0, 1][..]] {
            assert!(attrs(bytes).is_err());
        }
        assert!(messages(&[0; 16]).is_err());
        let mut m = Message::new(16, ACK, vec![0; 3]);
        m.attr(42, &[1, 2, 3]).unwrap();
        let b = m.encode(7);
        let parsed = messages(&b).unwrap();
        assert_eq!(parsed[0].seq, 7);
        assert_eq!(
            attrs(&parsed[0].payload[4..]).unwrap()[0],
            (42, &[1, 2, 3][..])
        );
    }
    #[test]
    fn real_unprivileged_link_dump() {
        let mut n = Netlink::new(libc::NETLINK_ROUTE, 0).unwrap();
        let replies = n.request(&Message::new(18, DUMP, vec![0; 16])).unwrap();
        assert!(replies.iter().any(|r| r.kind == 16));
    }
}
