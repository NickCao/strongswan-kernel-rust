// SPDX-License-Identifier: GPL-2.0-or-later
#![forbid(unsafe_code)]
use charon_kernel_daemon::{
    error::invalid,
    linux::interfaces::{name_prefix, DEFAULT_INTERFACE_GROUP},
    rpc_api,
    service::{Server, Service},
    transport,
};
use clap::Parser;
use nix::sys::{
    signal::Signal,
    signalfd::{SfdFlags, SignalFd},
};
use rustix::event::{poll, PollFd, PollFlags};
use std::{
    io,
    os::unix::net::{UnixListener, UnixStream},
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
    #[arg(long, default_value = "/run/charon-kernel/charon-kernel.sock")]
    socket: PathBuf,
    /// Socket access group, specified by name or numeric GID.
    #[arg(long, default_value = "0", value_name = "NAME|GID", value_parser = group_id)]
    group: u32,
    /// Prefix for daemon-owned XFRM interface names.
    #[arg(long, default_value = "ranet", value_parser = name_prefix)]
    ifname_prefix: String,
    /// Numeric link group reserved for daemon-owned interfaces.
    #[arg(long, default_value_t = DEFAULT_INTERFACE_GROUP, value_parser = clap::value_parser!(u32).range(1..))]
    interface_group: u32,
    /// Master device for daemon-owned XFRM interfaces.
    #[arg(long, value_name = "NAME", value_parser = interface_name)]
    master_device: Option<String>,
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
fn interface_name(value: &str) -> Result<String, String> {
    if value.is_empty() || value.len() >= libc::IFNAMSIZ || value.contains('\0') {
        return Err("expected an interface name shorter than 16 bytes".into());
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
        interface_group,
        master_device,
        mtu,
    } = Args::parse();
    rustix::process::umask(rustix::fs::Mode::from_bits_retain(0o077));
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)?;
    // Block before creating any workers so they inherit the mask. signalfd
    // delivers termination requests to the main loop in normal Rust context.
    let mask = Signal::SIGINT | Signal::SIGTERM;
    mask.thread_block()?;
    let signals = SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK)?;
    let listener = transport::listen(&path, gid)?;
    listener.set_nonblocking(true)?;
    eprintln!(
        "kernel-daemon: Varlink listening on {} with socket group {gid}",
        path.display()
    );
    let server = Arc::new(Server::new(prefix, master_device, mtu, interface_group));
    let result = serve(&listener, &signals, &server);
    let cleanup = server.shutdown();
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Stopping]);
    if let Err(error) = &cleanup {
        eprintln!("kernel-daemon: shutdown cleanup: {error}");
    }
    result.and(cleanup)
}
fn serve(listener: &UnixListener, signals: &SignalFd, server: &Arc<Server>) -> io::Result<()> {
    sd_notify::notify(&[sd_notify::NotifyState::Ready])?;
    let pending = Arc::new(AtomicUsize::new(0));
    loop {
        let mut ready = [
            PollFd::new(listener, PollFlags::IN),
            PollFd::new(signals, PollFlags::IN),
        ];
        match poll(&mut ready, None) {
            Err(rustix::io::Errno::INTR) => continue,
            result => result?,
        };
        if ready[1].revents().contains(PollFlags::IN) && signals.read_signal()?.is_some() {
            eprintln!("kernel-daemon: shutting down");
            return Ok(());
        }
        if !ready[0].revents().contains(PollFlags::IN) {
            continue;
        }
        let socket = match listener.accept() {
            Ok((socket, _)) => socket,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(error) => return Err(error),
        };
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
}
fn main() {
    if let Err(e) = run() {
        eprintln!("kernel-daemon: {e}");
        std::process::exit(1);
    }
}
