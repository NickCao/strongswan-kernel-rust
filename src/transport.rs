// SPDX-License-Identifier: GPL-2.0-or-later
//! Standard Varlink framing: bounded NUL-terminated JSON on a Unix stream.
use crate::error::invalid;
use std::{
    io::{self, Read},
    os::{
        fd::AsRawFd,
        unix::{
            fs::PermissionsExt,
            net::{UnixListener, UnixStream},
        },
    },
    path::Path,
};
use zeroize::Zeroizing;
pub const MAX_FRAME: usize = 131072;
pub fn peer(stream: &UnixStream) -> io::Result<libc::ucred> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as _,
            &mut len,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if len as usize != std::mem::size_of_val(&cred) {
        return Err(invalid());
    }
    Ok(cred)
}
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
pub struct Frames {
    pending: Zeroizing<Vec<u8>>,
}
impl Frames {
    pub fn read(&mut self, stream: &mut UnixStream) -> io::Result<Zeroizing<Vec<u8>>> {
        loop {
            if let Some(end) = self.pending.iter().position(|b| *b == 0) {
                let frame = Zeroizing::new(self.pending[..=end].to_vec());
                self.pending.drain(..=end);
                return Ok(frame);
            }
            if self.pending.len() >= MAX_FRAME {
                return Err(invalid());
            }
            let mut bytes = Zeroizing::new([0u8; 4096]);
            let room = bytes.len().min(MAX_FRAME - self.pending.len());
            match stream.read(&mut bytes[..room]) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => self.pending.extend_from_slice(&bytes[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }
    pub fn partial(&self) -> bool {
        !self.pending.is_empty()
    }
}

impl Default for Frames {
    fn default() -> Self {
        Self {
            pending: Zeroizing::new(Vec::with_capacity(MAX_FRAME)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, thread};

    #[test]
    fn fragmented_and_coalesced_frames() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let thread = thread::spawn(move || {
            writer.write_all(b"{\"method\":").unwrap();
            writer.write_all(b"\"one\"}\0{}\0").unwrap();
        });
        let mut frames = Frames::default();
        assert_eq!(
            &*frames.read(&mut reader).unwrap(),
            b"{\"method\":\"one\"}\0"
        );
        assert_eq!(&*frames.read(&mut reader).unwrap(), b"{}\0");
        thread.join().unwrap();
        assert_eq!(
            frames.read(&mut reader).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn oversized_unterminated_frame_is_rejected() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let thread = thread::spawn(move || {
            let _ = writer.write_all(&vec![b'x'; MAX_FRAME + 1]);
        });
        assert_eq!(
            Frames::default()
                .read(&mut reader)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );
        drop(reader);
        thread.join().unwrap();
    }
}
