// SPDX-License-Identifier: GPL-2.0-or-later
//! Unix peer credentials shared by the client and server.
use std::{io, os::unix::net::UnixStream};
#[derive(Clone, Copy, Debug)]
pub struct Peer {
    pub uid: u32,
    pub pid: i32,
}
pub fn peer(stream: &UnixStream) -> io::Result<Peer> {
    // Across PID namespaces SO_PEERCRED may return pid 0. Keep the raw pid_t:
    // a NonZero/Pid credential representation would have an invalid invariant.
    let cred = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)?;
    Ok(Peer {
        uid: cred.uid(),
        pid: cred.pid(),
    })
}

pub type Framed<In, Out> = tarpc::serde_transport::Transport<
    tokio::net::UnixStream,
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
    tarpc::serde_transport::new(codec, tarpc::tokio_serde::formats::Bincode::default())
}
