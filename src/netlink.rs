// SPDX-License-Identifier: GPL-2.0-or-later
use crate::{error::invalid, uapi::*};
use std::{
    io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};
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
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                protocol,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as _;
        addr.nl_groups = groups;
        if unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const _ as _,
                mem::size_of_val(&addr) as _,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        let on: i32 = 1;
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_NETLINK,
                libc::NETLINK_EXT_ACK,
                &on as *const _ as _,
                4,
            );
        }
        let rcv: i32 = 4 * 1024 * 1024;
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &rcv as *const _ as _,
                4,
            );
        }
        let timeout = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        if unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const _ as _,
                mem::size_of_val(&timeout) as _,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, seq: 0 })
    }
    pub fn raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
    pub fn receive(&self) -> io::Result<Vec<Reply>> {
        // Peek size instead of silently truncating large dumps or replay maps.
        let mut one = 0u8;
        let len = loop {
            let n = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    &mut one as *mut _ as _,
                    1,
                    libc::MSG_PEEK | libc::MSG_TRUNC,
                )
            };
            if n >= 0 {
                break n as usize;
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        };
        if len == 0 || len > 4 * 1024 * 1024 {
            return Err(invalid());
        }
        let mut b = Zeroizing::new(vec![0; len]);
        let mut sender: libc::sockaddr_nl = unsafe { mem::zeroed() };
        let mut sender_len = mem::size_of_val(&sender) as libc::socklen_t;
        let n = unsafe {
            libc::recvfrom(
                self.fd.as_raw_fd(),
                b.as_mut_ptr() as _,
                b.len(),
                0,
                &mut sender as *mut _ as _,
                &mut sender_len,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if sender.nl_pid != 0 {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        if n as usize != len {
            return Err(invalid());
        }
        messages(&b)
    }
    pub fn request(&mut self, msg: &Message) -> io::Result<Vec<Reply>> {
        self.seq = self.seq.wrapping_add(1).max(1);
        let seq = self.seq;
        let b = msg.encode(seq);
        let mut dest: libc::sockaddr_nl = unsafe { mem::zeroed() };
        dest.nl_family = libc::AF_NETLINK as _;
        loop {
            let n = unsafe {
                libc::sendto(
                    self.fd.as_raw_fd(),
                    b.as_ptr() as _,
                    b.len(),
                    0,
                    &dest as *const _ as _,
                    mem::size_of_val(&dest) as _,
                )
            };
            if n >= 0 {
                if n as usize != b.len() {
                    return Err(invalid());
                }
                break;
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
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
