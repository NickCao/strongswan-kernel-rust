// SPDX-License-Identifier: GPL-2.0-or-later
#![forbid(unsafe_code)]
use charon_kernel_daemon::{
    linux::interfaces::{name_prefix, DEFAULT_INTERFACE_GROUP},
    rpc_api::notification::Notification,
    rpc_api::Kernel,
    service::{Server, Service},
    transport,
};
use clap::Parser;
use futures::StreamExt;
use nix::sys::signal::Signal;
use std::{io, os::unix::net::UnixStream, path::PathBuf, sync::Arc};
use tarpc::server::Channel;
use tokio::{
    net::UnixListener,
    signal::unix::{signal, Signal as SignalStream, SignalKind},
    task::JoinSet,
};

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
async fn connection(socket: UnixStream, server: Arc<Server>) -> io::Result<()> {
    let notification = Notification::new()?;
    notification.send(&socket)?;
    socket.set_nonblocking(true)?;
    let service = Service::new(server, socket.try_clone()?);
    let socket = tokio::net::UnixStream::from_std(socket)?;
    let notifications = async {
        while service.next_notification().await.is_some() {
            notification.notify()?;
        }
        Ok::<_, io::Error>(())
    };
    tokio::pin!(notifications);
    let mut notifying = true;
    let transport = charon_kernel_daemon::rpc_api::transport::framed(socket);
    let channel = tarpc::server::BaseChannel::with_defaults(transport);
    let mut requests = channel.requests();
    let mut tasks = JoinSet::new();
    let result = loop {
        tokio::select! {
            result = &mut notifications, if notifying => {
                if let Err(error) = result { break Err(error); }
                notifying = false;
            },
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
    // Block termination until Tokio installs its handlers. The same runtime
    // drives RPCs, signals, Netlink notifications and shutdown cleanup.
    let mask = Signal::SIGINT | Signal::SIGTERM;
    mask.thread_block()?;
    let listener = transport::listen(&path, gid)?;
    listener.set_nonblocking(true)?;
    eprintln!(
        "kernel-daemon: tarpc listening on {} with socket group {gid}",
        path.display()
    );
    let server = Arc::new(Server::new(prefix, master_device, mtu, interface_group)?);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let listener = UnixListener::from_std(listener)?;
            let mut interrupt = signal(SignalKind::interrupt())?;
            let mut terminate = signal(SignalKind::terminate())?;
            mask.thread_unblock()?;
            let mut connections = JoinSet::new();
            let result = serve(
                &listener,
                &mut interrupt,
                &mut terminate,
                &server,
                &mut connections,
            )
            .await;
            let _ = sd_notify::notify(&[sd_notify::NotifyState::Stopping]);
            let cleanup = server.shutdown().await;
            if let Err(error) = &cleanup {
                eprintln!("kernel-daemon: shutdown cleanup: {error}");
            }
            connections.shutdown().await;
            result.and(cleanup)
        })
}
async fn termination(interrupt: &mut SignalStream, terminate: &mut SignalStream) {
    tokio::select! {
        _ = interrupt.recv() => (),
        _ = terminate.recv() => (),
    }
}
async fn serve(
    listener: &UnixListener,
    interrupt: &mut SignalStream,
    terminate: &mut SignalStream,
    server: &Arc<Server>,
    connections: &mut JoinSet<()>,
) -> io::Result<()> {
    sd_notify::notify(&[sd_notify::NotifyState::Ready])?;
    loop {
        tokio::select! {
            _ = termination(interrupt, terminate) => {
                eprintln!("kernel-daemon: shutting down");
                return Ok(());
            },
            _ = server.session_failure().notified() => {
                eprintln!("kernel-daemon: active session lost; shutting down");
                return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "active kernel session lost"));
            },
            accepted = listener.accept() => {
                let (socket, _) = match accepted {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => result?,
                };
                // The filesystem socket's 0660 mode authorizes clients,
                // including supplementary groups and DynamicUser clients.
                if connections.len() >= 8 {
                    continue;
                }
                let (socket, server) = (socket.into_std()?, server.clone());
                connections.spawn(async move {
                    if let Err(error) = connection(socket, server).await {
                        if error.kind() != io::ErrorKind::UnexpectedEof {
                            eprintln!("kernel-daemon: client connection closed ({:?})", error.kind());
                        }
                    }
                });
            },
            _ = connections.join_next(), if !connections.is_empty() => (),
        }
    }
}
fn main() {
    if let Err(e) = run() {
        eprintln!("kernel-daemon: {e}");
        std::process::exit(1);
    }
}
