// SPDX-License-Identifier: GPL-2.0-or-later
//! Filesystem socket setup; tarpc owns the protocol.
use std::{
    io,
    os::unix::{fs::PermissionsExt, net::UnixListener},
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
