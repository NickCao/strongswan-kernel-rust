// SPDX-License-Identifier: GPL-2.0-or-later
//! Standard Varlink framing: bounded NUL-terminated JSON on a Unix stream.
use crate::error::invalid;
pub use kernel_rust_protocol::transport::{peer, Frames, MAX_FRAME};
use std::{
    io,
    os::{
        fd::AsRawFd,
        unix::{
            fs::PermissionsExt,
            net::{UnixListener, UnixStream},
        },
    },
    path::Path,
};
pub fn listen(path: &Path, uid: u32, gid: u32) -> io::Result<UnixListener> {
    let listener = UnixListener::bind(path)?;
    let path_c =
        std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| invalid())?;
    if unsafe { libc::chown(path_c.as_ptr(), uid, gid) } < 0 {
        return Err(io::Error::last_os_error());
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}
pub fn disconnected(stream: &UnixStream) -> bool {
    let mut b = 0u8;
    let ret = unsafe {
        libc::recv(
            stream.as_raw_fd(),
            &mut b as *mut _ as _,
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    ret == 0
        || (ret < 0
            && !matches!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::EAGAIN | libc::EINTR)
            ))
}
