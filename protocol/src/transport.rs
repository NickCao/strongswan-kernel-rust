// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded, standard Varlink frames shared by the client and server.
use rustix::net::{recv, RecvFlags};
use std::{io, os::unix::net::UnixStream};
use zeroize::{Zeroize, Zeroizing};
pub const MAX_FRAME: usize = 131072;
fn invalid() -> io::Error {
    io::Error::from_raw_os_error(libc::EINVAL)
}
#[derive(Clone, Copy, Debug)]
pub struct Peer {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
}
pub fn peer(stream: &UnixStream) -> io::Result<Peer> {
    // Across PID namespaces SO_PEERCRED may return pid 0. Keep the raw pid_t:
    // a NonZero/Pid credential representation would have an invalid invariant.
    let cred = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)?;
    Ok(Peer {
        uid: cred.uid(),
        gid: cred.gid(),
        pid: cred.pid(),
    })
}
pub struct Frames {
    pending: Zeroizing<Vec<u8>>,
}
impl Frames {
    pub fn read(&mut self, stream: &mut UnixStream) -> io::Result<Zeroizing<Vec<u8>>> {
        self.read_flags(stream, RecvFlags::empty())
    }
    pub fn read_flags(
        &mut self,
        stream: &UnixStream,
        flags: RecvFlags,
    ) -> io::Result<Zeroizing<Vec<u8>>> {
        loop {
            if let Some(end) = self.pending.iter().position(|b| *b == 0) {
                let frame = Zeroizing::new(self.pending[..=end].to_vec());
                let remaining = self.pending.len() - end - 1;
                self.pending.copy_within(end + 1.., 0);
                self.pending[remaining..].zeroize();
                self.pending.truncate(remaining);
                return Ok(frame);
            }
            if self.pending.len() >= MAX_FRAME {
                return Err(invalid());
            }
            let mut bytes = Zeroizing::new([0u8; 4096]);
            let room = bytes.len().min(MAX_FRAME - self.pending.len());
            let result = recv(stream, &mut bytes[..room], flags)
                .map(|(n, _)| n)
                .map_err(io::Error::from);
            match result {
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

    #[test]
    fn nonblocking_read_retains_partial_and_coalesced_events() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let mut frames = Frames::default();
        writer.write_all(b"{\"event\":").unwrap();
        assert_eq!(
            frames
                .read_flags(&reader, RecvFlags::DONTWAIT)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        writer.write_all(b"1}\0{\"event\":2}\0{\"event\":").unwrap();
        assert_eq!(
            &*frames.read_flags(&reader, RecvFlags::DONTWAIT).unwrap(),
            b"{\"event\":1}\0"
        );
        assert_eq!(
            &*frames.read_flags(&reader, RecvFlags::DONTWAIT).unwrap(),
            b"{\"event\":2}\0"
        );
        assert_eq!(
            frames
                .read_flags(&reader, RecvFlags::DONTWAIT)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        writer.write_all(b"3}\0").unwrap();
        assert_eq!(
            &*frames.read_flags(&reader, RecvFlags::DONTWAIT).unwrap(),
            b"{\"event\":3}\0"
        );
    }
}
