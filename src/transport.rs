// SPDX-License-Identifier: GPL-2.0-or-later
//! Standard Varlink framing: bounded NUL-terminated JSON on a Unix stream.
pub use kernel_rust_protocol::transport::{peer, Frames, Peer, MAX_FRAME};
use rustix::net::{recv, RecvFlags};
use std::{
    io,
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::Path,
};
pub fn listen(path: &Path, gid: u32) -> io::Result<UnixListener> {
    let listener = UnixListener::bind(path)?;
    // Keep the socket owned by the daemon. Client access is through its group,
    // so recycled dynamic client UIDs never retain ownership of this path.
    std::os::unix::fs::chown(path, None, Some(gid))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}
pub fn disconnected(stream: &UnixStream) -> bool {
    match recv(stream, &mut [0u8], RecvFlags::PEEK | RecvFlags::DONTWAIT) {
        Ok((0, _)) => true,
        Ok(_) | Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => false,
        Err(_) => true,
    }
}
