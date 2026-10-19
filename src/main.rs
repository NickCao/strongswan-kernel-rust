// SPDX-License-Identifier: GPL-2.0-or-later
#![forbid(unsafe_code)]
use charon_kernel_daemon::{
    error::invalid,
    rpc_api,
    service::{Server, Service},
    transport,
};
use clap::Parser;
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

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Filesystem path for the Varlink socket.
    #[arg(long, default_value = "/run/charon-kernel.sock")]
    socket: PathBuf,
    /// Socket access group, specified by name or numeric GID.
    #[arg(long, default_value = "0", value_name = "NAME|GID", value_parser = group_id)]
    group: u32,
    /// Prefix for daemon-owned XFRM interface names.
    #[arg(long, default_value = "ranet", value_parser = interface_prefix)]
    ifname_prefix: String,
    /// MTU of daemon-owned XFRM interfaces.
    #[arg(long, default_value_t = 1400, value_parser = clap::value_parser!(u32).range(1280..=65535))]
    mtu: u32,
}
fn group_id(value: &str) -> Result<u32, String> {
    if let Ok(gid) = value.parse() {
        return Ok(gid);
    }
    nix::unistd::Group::from_name(value)
        .map_err(|error| error.to_string())?
        .map(|group| group.gid.as_raw())
        .ok_or_else(|| format!("unknown group {value:?}"))
}
fn interface_prefix(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() + 8 >= libc::IFNAMSIZ
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err("expected 1–7 ASCII letters, digits, underscores, or hyphens".into());
    }
    Ok(value.to_owned())
}
fn connection(
    mut socket: UnixStream,
    peer: transport::Peer,
    server: Arc<Server>,
) -> io::Result<()> {
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
    let mut reader = io::BufReader::new(socket.try_clone()?);
    // Varlink owns request framing and generated dispatch. Error payloads may
    // contain key material, so only report an error kind to the accept loop.
    loop {
        match dispatcher.handle(&mut reader, &mut socket, None) {
            // Generated dispatch has already replied InvalidParameter; the
            // connection remains usable for a subsequent semantic request.
            Err(error) if matches!(error.kind(), varlink::ErrorKind::SerdeJsonDe(_)) => continue,
            Err(error) if matches!(error.kind(), varlink::ErrorKind::ConnectionClosed) => {
                return Ok(())
            }
            Ok((unread, None)) if unread.is_empty() => return Ok(()),
            _ => return Err(invalid()),
        }
    }
}
fn run() -> io::Result<()> {
    let Args {
        socket: path,
        group: gid,
        ifname_prefix: prefix,
        mtu,
    } = Args::parse();
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
