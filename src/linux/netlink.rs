// SPDX-License-Identifier: GPL-2.0-or-later
//! Async Netlink requests and notifications through neli. Payloads are encoded by
//! netlink-packet-route and netlink-packet-xfrm and remain opaque here.
pub use neli::consts::{nl::NlmF, socket::NlFamily};
use neli::{
    err::{RouterError, SocketError},
    genl::Genlmsghdr,
    nl::{NlPayload, Nlmsghdr},
    router::asynchronous::{NlRouter, NlRouterReceiverHandle},
    types::Buffer,
    utils::Groups,
};
use netlink_packet_core::Emitable;
use std::{
    io,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

// Leave room for RPC error delivery within the client's ten-second deadline.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn transport_failed(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::BrokenPipe
    )
}

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
        RouterError::ClosedChannel => io::Error::from_raw_os_error(libc::EPIPE),
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
    failed: AtomicBool,
}
impl Netlink {
    pub async fn new(family: NlFamily) -> io::Result<Self> {
        Self::subscribe(family, 0).await.map(|(socket, _)| socket)
    }
    pub async fn subscribe(family: NlFamily, groups: u32) -> io::Result<(Self, Notifications)> {
        let (router, receiver) = NlRouter::connect(family, None, Groups::new_bitmask(groups))
            .await
            .map_err(router_error)?;
        Ok((
            Self {
                router,
                failed: AtomicBool::new(false),
            },
            Notifications { receiver },
        ))
    }
    pub async fn request(&self, message: &Message) -> io::Result<Vec<Reply>> {
        if self.failed.load(Ordering::Acquire) {
            return Err(io::Error::from_raw_os_error(libc::EPIPE));
        }
        let result = tokio::time::timeout(REQUEST_TIMEOUT, self.exchange(message))
            .await
            .unwrap_or_else(|_| Err(io::Error::from_raw_os_error(libc::ETIMEDOUT)));
        // A timed-out mutation may already have reached the kernel. Do not
        // reuse this transport or automatically replay the operation.
        if result.as_ref().is_err_and(transport_failed) {
            self.failed.store(true, Ordering::Release);
        }
        result
    }
    async fn exchange(&self, message: &Message) -> io::Result<Vec<Reply>> {
        let mut receiver = self
            .router
            .send::<_, _, u16, Buffer>(
                message.kind,
                message.flags,
                NlPayload::Payload(Buffer::from(message.payload.as_slice())),
            )
            .await
            .map_err(router_error)?;
        let mut replies = Vec::new();
        while let Some(message) = receiver.next::<u16, Buffer>().await {
            if let Some(reply) = reply(message.map_err(router_error)?)? {
                replies.push(reply);
            }
        }
        Ok(replies)
    }
    pub async fn ack(&self, message: &Message) -> io::Result<()> {
        self.request(message).await.map(|_| ())
    }
}

pub struct Notifications {
    receiver: NlRouterReceiverHandle<u16, Genlmsghdr<u8, u16>>,
}
impl Notifications {
    pub async fn next(&mut self) -> Option<io::Result<Reply>> {
        loop {
            let message = self.receiver.next::<u16, Buffer>().await?;
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

    #[tokio::test(flavor = "current_thread")]
    async fn real_unprivileged_link_dump() {
        let netlink = Netlink::new(NlFamily::Route).await.unwrap();
        let request = RouteNetlinkMessage::GetLink(LinkMessage::default());
        let replies = netlink
            .request(&Message::new(request.message_type(), NlmF::DUMP, &request))
            .await
            .unwrap();
        assert!(replies.iter().any(|reply| matches!(
            RouteNetlinkMessage::parse_with_param(&reply.payload, reply.kind).unwrap(),
            RouteNetlinkMessage::NewLink(_)
        )));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unanswered_request_times_out_and_stops_reusing_the_socket() {
        let netlink = Netlink::new(NlFamily::Route).await.unwrap();
        // Linux ignores NLMSG_NOOP when no ACK was requested. This used to
        // leave the response iterator waiting without a bound.
        let message = Message {
            kind: libc::NLMSG_NOOP as u16,
            flags: NlmF::empty(),
            payload: Vec::new(),
        };
        let result = tokio::time::timeout(
            REQUEST_TIMEOUT + Duration::from_secs(1),
            netlink.request(&message),
        )
        .await
        .unwrap();
        assert_eq!(result.err().unwrap().raw_os_error(), Some(libc::ETIMEDOUT));
        assert_eq!(
            netlink
                .request(&message)
                .await
                .err()
                .unwrap()
                .raw_os_error(),
            Some(libc::EPIPE)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dropping_subscription_wakes_the_notification_reader() {
        let (socket, mut notifications) = Netlink::subscribe(NlFamily::Route, 1).await.unwrap();
        let reader = tokio::spawn(async move { notifications.next().await });
        tokio::task::yield_now().await;
        drop(socket);
        let result = tokio::time::timeout(Duration::from_secs(1), reader)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            result.unwrap().err().unwrap().raw_os_error(),
            Some(libc::EPIPE)
        );
    }
}
