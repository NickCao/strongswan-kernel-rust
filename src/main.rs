// SPDX-License-Identifier: GPL-2.0-or-later
#![forbid(unsafe_code)]
use charon_kernel_daemon::{
    error::invalid,
    rpc_api,
    service::{Server, Service},
    transport::{self, Frames},
};
use std::{
    io,
    os::unix::net::UnixStream,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use varlink::ConnectionHandler;
fn connection(
    mut socket: UnixStream,
    peer: transport::Peer,
    server: Arc<Server>,
) -> io::Result<()> {
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    socket.set_write_timeout(Some(Duration::from_secs(10)))?;
    let service = Service {
        server,
        socket: socket.try_clone()?,
        peer,
        control: Mutex::new(None),
    };
    let dispatcher = varlink::VarlinkService::new(
        "ranet",
        "IPsec kernel backend",
        env!("CARGO_PKG_VERSION"),
        "https://github.com/NickCao/ranet",
        vec![Box::new(rpc_api::new(Box::new(service)))],
    );
    let mut frames = Frames::default();
    loop {
        let frame = match frames.read(&mut socket) {
            Ok(f) => f,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) && !frames.partial() =>
            {
                continue
            }
            Err(e) => return Err(e),
        };
        // A single bounded standard Varlink frame is dispatched by the generated
        // interface. Never log parse errors, which may contain key material.
        let (unread, upgraded) =
            match dispatcher.handle(&mut io::Cursor::new(&frame[..]), &mut socket, None) {
                Ok(v) => v,
                Err(e) if matches!(e.kind(), varlink::ErrorKind::SerdeJsonDe(_)) => continue,
                Err(_) => return Err(invalid()),
            };
        if !unread.is_empty() || upgraded.is_some() {
            return Err(invalid());
        }
    }
}
fn run() -> io::Result<()> {
    let mut path = PathBuf::from("/run/charon-kernel.sock");
    let (mut gid, mut mtu) = (0, 1400);
    let mut prefix = "ranet".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => path = args.next().ok_or_else(invalid)?.into(),
            "--group" => {
                let group = args.next().ok_or_else(invalid)?;
                gid = match group.parse() {
                    Ok(gid) => gid,
                    Err(_) => nix::unistd::Group::from_name(&group)?
                        .ok_or_else(invalid)?
                        .gid
                        .as_raw(),
                };
            }
            "--mtu" => {
                mtu = args
                    .next()
                    .ok_or_else(invalid)?
                    .parse()
                    .map_err(|_| invalid())?
            }
            "--ifname-prefix" => prefix = args.next().ok_or_else(invalid)?,
            "--help" => {
                println!("charon-kernel-daemon [--socket PATH] [--group NAME|GID] [--ifname-prefix ranet] [--mtu 1400]");
                return Ok(());
            }
            _ => return Err(invalid()),
        }
    }
    if prefix.is_empty()
        || prefix.len() + 8 >= libc::IFNAMSIZ
        || !prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        || !(1280..=65535).contains(&mtu)
    {
        return Err(invalid());
    }
    rustix::process::umask(rustix::fs::Mode::from_bits_retain(0o077));
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)?;
    let listener = transport::listen(&path, gid)?;
    eprintln!(
        "kernel-daemon: Varlink listening on {} with socket group {gid}",
        path.display()
    );
    let server = Arc::new(Server {
        active: Mutex::new(None),
        prefix,
        mtu,
    });
    let pending = Arc::new(AtomicUsize::new(0));
    for socket in listener.incoming() {
        let socket = socket?;
        let peer = transport::peer(&socket)?;
        // The filesystem socket's 0660 mode authorizes the connecting process,
        // including its supplementary groups. SO_PEERCRED only reports its
        // primary GID, so checking that here would break DynamicUser clients.
        // Bind the control and event connections to their actual PID/UID below.
        if pending.fetch_add(1, Ordering::AcqRel) >= 8 {
            pending.fetch_sub(1, Ordering::AcqRel);
            continue;
        }
        let (server, pending) = (server.clone(), pending.clone());
        thread::spawn(move || {
            if let Err(e) = connection(socket, peer, server) {
                if e.kind() != io::ErrorKind::UnexpectedEof {
                    eprintln!("kernel-daemon: client connection closed ({:?})", e.kind());
                }
            }
            pending.fetch_sub(1, Ordering::AcqRel);
        });
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("kernel-daemon: {e}");
        std::process::exit(1);
    }
}
