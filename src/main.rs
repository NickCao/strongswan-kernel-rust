// SPDX-License-Identifier: GPL-2.0-or-later
#![forbid(unsafe_code)]
use charon_kernel_daemon::{
    linux::interfaces::{name_prefix, DEFAULT_INTERFACE_GROUP},
    rpc_api::Kernel,
    service::{Server, Service},
    transport,
};
use clap::Parser;
use futures::StreamExt;
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
        Arc,
    },
    thread,
};
use tarpc::server::Channel;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Filesystem path for the tarpc socket.
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
fn connection(socket: UnixStream, peer: transport::Peer, server: Arc<Server>) -> io::Result<()> {
    socket.set_nonblocking(true)?;
    let service = Service::new(server, socket.try_clone()?, peer);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let socket = tokio::net::UnixStream::from_std(socket)?;
        let channel = tarpc::server::BaseChannel::with_defaults(
            charon_kernel_daemon::rpc_api::transport::framed(socket),
        );
        let mut requests = channel.requests();
        let mut tasks = tokio::task::JoinSet::new();
        let result = loop {
            tokio::select! {
                request = requests.next() => match request {
                    Some(Ok(request)) => { tasks.spawn(request.execute(service.clone().serve())); }
                    // Do not log decode errors: a failed frame can contain keys.
                    Some(Err(error)) => {
                        use tarpc::ChannelError::*;
                        let kind = match error {
                            Read(error) | Ready(error) | Write(error) | Flush(error) | Close(error) => error.kind(),
                        };
                        break if matches!(kind, io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe) {
                            Ok(())
                        } else { Err(kind.into()) };
                    },
                    None => break Ok(()),
                },
                _ = tasks.join_next(), if !tasks.is_empty() => (),
            }
        };
        tasks.shutdown().await;
        result
    })
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
        "kernel-daemon: tarpc listening on {} with socket group {gid}",
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
