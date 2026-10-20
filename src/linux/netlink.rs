// SPDX-License-Identifier: GPL-2.0-or-later
//! Netlink requests and notifications through neli. Payloads are encoded by
//! netlink-packet-route and netlink-packet-xfrm and remain opaque here.
pub use neli::consts::{nl::NlmF, socket::NlFamily};
use neli::{
    err::{RouterError, SocketError},
    genl::Genlmsghdr,
    nl::{NlPayload, Nlmsghdr},
    router::synchronous::{NlRouter, NlRouterReceiverHandle},
    types::Buffer,
    utils::Groups,
};
use netlink_packet_core::Emitable;
use std::io;

pub struct Message {
    pub kind: u16,
    pub flags: NlmF,
    pub payload: Vec<u8>,
}
impl Message {
    pub fn new(kind: u16, flags: NlmF, value: &impl Emitable) -> Self {
        let mut payload = vec![0; value.buffer_len()];
        value.emit(&mut payload);
        Self {
            kind,
            flags,
            payload,
        }
    }
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
        let receiver = self
            .router
            .send::<_, _, u16, Buffer>(
                message.kind,
                message.flags,
                NlPayload::Payload(Buffer::from(message.payload.as_slice())),
            )
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
    use netlink_packet_core::ParseableParametrized;
    use netlink_packet_route::{link::LinkMessage, RouteNetlinkMessage};

    #[test]
    fn real_unprivileged_link_dump() {
        let netlink = Netlink::new(NlFamily::Route).unwrap();
        let request = RouteNetlinkMessage::GetLink(LinkMessage::default());
        let replies = netlink
            .request(&Message::new(request.message_type(), NlmF::DUMP, &request))
            .unwrap();
        assert!(replies.iter().any(|reply| matches!(
            RouteNetlinkMessage::parse_with_param(&reply.payload, reply.kind).unwrap(),
            RouteNetlinkMessage::NewLink(_)
        )));
    }
}
