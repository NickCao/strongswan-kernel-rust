// SPDX-License-Identifier: GPL-2.0-or-later
//! Netlink requests and notifications through neli. XFRM payloads are encoded
//! by netlink-packet-xfrm and remain opaque at this transport layer.
use crate::error::invalid;
pub use neli::consts::{nl::NlmF, socket::NlFamily};
use neli::{
    err::{RouterError, SocketError},
    genl::Genlmsghdr,
    nl::{NlPayload, Nlmsghdr},
    router::synchronous::{NlRouter, NlRouterReceiverHandle},
    rtnl::{Rtattr, RtattrBuilder},
    types::{Buffer, RtBuffer},
    utils::Groups,
    FromBytesWithInput, Size, ToBytes,
};
use std::io::{self, Cursor};

pub fn align(n: usize) -> usize {
    neli::consts::alignto(n)
}

pub struct Message {
    pub kind: u16,
    pub flags: NlmF,
    pub payload: Vec<u8>,
}
impl Message {
    pub fn new(kind: u16, flags: NlmF, payload: Vec<u8>) -> Self {
        Self {
            kind,
            flags,
            payload,
        }
    }
}

pub fn get16(bytes: &[u8], offset: usize) -> u16 {
    netlink_packet_core::parse_u16(&bytes[offset..offset + 2]).unwrap()
}
pub fn get32(bytes: &[u8], offset: usize) -> u32 {
    netlink_packet_core::parse_u32(&bytes[offset..offset + 4]).unwrap()
}

pub fn attribute<T: Size, P: Size + ToBytes>(kind: T, payload: P) -> io::Result<Rtattr<T, Buffer>> {
    if payload.unpadded_size() > u16::MAX as usize - 4 {
        return Err(invalid());
    }
    RtattrBuilder::default()
        .rta_type(kind)
        .rta_payload(payload)
        .build()
        .map_err(io::Error::other)
}

pub struct Attributes(RtBuffer<u16, Buffer>);
impl Attributes {
    pub fn iter(&self) -> impl Iterator<Item = (u16, &[u8])> {
        self.0
            .iter()
            .map(|attr| (*attr.rta_type() & 0x3fff, attr.rta_payload().as_ref()))
    }
}
pub fn attrs(data: &[u8]) -> io::Result<Attributes> {
    RtBuffer::from_bytes_with_input(&mut Cursor::new(data), data.len())
        .map(Attributes)
        .map_err(|_| invalid())
}

pub struct Reply {
    pub kind: u16,
    pub payload: Vec<u8>,
}
fn reply(message: Nlmsghdr<u16, Buffer>) -> io::Result<Option<Reply>> {
    if message.nl_flags().contains(NlmF::DUMP_INTR) {
        return Err(io::Error::from_raw_os_error(libc::EINTR));
    }
    if *message.nl_type() == libc::NLMSG_OVERRUN as u16 {
        return Err(io::Error::from_raw_os_error(libc::ENOBUFS));
    }
    match message.nl_payload() {
        NlPayload::Payload(payload) => Ok(Some(Reply {
            kind: *message.nl_type(),
            payload: payload.as_ref().to_vec(),
        })),
        NlPayload::DumpExtAck(done) if *done.error() != 0 => {
            Err(io::Error::from_raw_os_error(-done.error()))
        }
        _ => Ok(None),
    }
}
fn router_error<T: std::fmt::Debug, P: std::fmt::Debug>(error: RouterError<T, P>) -> io::Error {
    match error {
        RouterError::Nlmsgerr(error) => io::Error::from_raw_os_error(-error.error()),
        RouterError::Io(kind) => kind.into(),
        RouterError::Socket(SocketError::Io(error)) => match error.raw_os_error() {
            Some(errno) => io::Error::from_raw_os_error(errno),
            None => error.kind().into(),
        },
        other => io::Error::other(other.to_string()),
    }
}

pub struct Netlink {
    router: NlRouter,
}
impl Netlink {
    pub fn new(family: NlFamily) -> io::Result<Self> {
        Self::subscribe(family, 0).map(|(socket, _)| socket)
    }
    pub fn subscribe(family: NlFamily, groups: u32) -> io::Result<(Self, Notifications)> {
        let (router, receiver) =
            NlRouter::connect(family, None, Groups::new_bitmask(groups)).map_err(router_error)?;
        Ok((Self { router }, Notifications { receiver }))
    }
    pub fn request(&self, message: &Message) -> io::Result<Vec<Reply>> {
        self.request_payload(
            message.kind,
            message.flags,
            Buffer::from(message.payload.as_slice()),
        )
    }
    pub fn request_payload<P: Size + ToBytes>(
        &self,
        kind: u16,
        flags: NlmF,
        payload: P,
    ) -> io::Result<Vec<Reply>> {
        let receiver = self
            .router
            .send::<_, _, u16, Buffer>(kind, flags, NlPayload::Payload(payload))
            .map_err(router_error)?;
        let mut replies = Vec::new();
        for message in receiver {
            if let Some(reply) = reply(message.map_err(router_error)?)? {
                replies.push(reply);
            }
        }
        Ok(replies)
    }
    pub fn ack(&self, message: &Message) -> io::Result<()> {
        self.request(message).map(|_| ())
    }
}

pub struct Notifications {
    receiver: NlRouterReceiverHandle<u16, Genlmsghdr<u8, u16>>,
}
impl Iterator for Notifications {
    type Item = io::Result<Reply>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let message = self.receiver.next_typed::<u16, Buffer>()?;
            match message.map_err(router_error).and_then(reply) {
                Ok(Some(reply)) => return Some(Ok(reply)),
                Ok(None) => (),
                Err(error) => return Some(Err(error)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_attributes() {
        for bytes in [&[1u8, 0, 1, 0][..], &[8, 0, 1, 0][..], &[4, 0, 1][..]] {
            assert!(attrs(bytes).is_err());
        }
    }

    #[test]
    fn real_unprivileged_link_dump() {
        let netlink = Netlink::new(NlFamily::Route).unwrap();
        let replies = netlink
            .request(&Message::new(18u16, NlmF::DUMP, vec![0; 16]))
            .unwrap();
        assert!(replies.iter().any(|reply| reply.kind == 16));
    }
}
