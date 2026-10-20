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
