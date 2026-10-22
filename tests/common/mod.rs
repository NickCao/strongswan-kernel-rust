// SPDX-License-Identifier: GPL-2.0-or-later
pub mod netns;

use charon_kernel_daemon::linux::{
    netlink::{Message, Netlink, NlFamily, NlmF},
    network::{Link, Network},
};
use kernel_rust_protocol::{notification::Notification, transport, *};
use netlink_packet_core::Parseable;
use netlink_packet_xfrm::{state::ModifyMessage, XfrmMessage, XFRM_MSG_GETSA};
use nix::{
    sys::signal::{kill, Signal},
    unistd::Pid,
};
use std::{
    fs::{self, File},
    future::Future,
    net::Shutdown,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};
use tokio::runtime::Runtime;

pub fn eventually(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "condition did not converge within 10 seconds"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

pub fn ip(args: &[&str]) -> String {
    let output = Command::new("ip")
        .args(args)
        .output()
        .expect("iproute2 is required");
    assert!(
        output.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

pub fn links() -> Vec<Link> {
    let mut network = Network::new().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match network.links() {
            // The daemon may change links during a dump. Discard the partial
            // inventory and observe again, as a later reconciliation would.
            Err(error)
                if error.kind() == std::io::ErrorKind::Interrupted && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(20));
            }
            result => return result.unwrap(),
        }
    }
}
pub fn owned_links() -> Vec<Link> {
    links().into_iter().filter(|l| l.group == 17227).collect()
}
pub fn states() -> Vec<ModifyMessage> {
    Netlink::new(NlFamily::Xfrm)
        .unwrap()
        .request(&Message::new(
            XFRM_MSG_GETSA,
            NlmF::DUMP,
            &XfrmMessage::GetSa(Default::default()),
        ))
        .unwrap()
        .into_iter()
        .map(|r| ModifyMessage::parse(r.payload.as_slice()).unwrap())
        .collect()
}

#[derive(Clone, Copy, Debug)]
pub enum Family {
    V4,
    V6,
}
impl Family {
    pub fn local(self) -> Endpoint {
        self.host("192.0.2.1", "2001:db8:1::1")
    }
    pub fn peer(self) -> Endpoint {
        self.host("192.0.2.2", "2001:db8:1::2")
    }
    pub fn destination(self) -> Endpoint {
        self.host("203.0.113.2", "2001:db8:2::2")
    }
    pub fn gateway(self) -> Endpoint {
        self.host("192.0.2.254", "2001:db8:1::fe")
    }
    pub fn host(self, v4: &str, v6: &str) -> Endpoint {
        Endpoint::new(
            match self {
                Self::V4 => v4,
                Self::V6 => v6,
            }
            .parse()
            .unwrap(),
            13000,
        )
    }
    pub fn af(self) -> u16 {
        (match self {
            Self::V4 => libc::AF_INET,
            Self::V6 => libc::AF_INET6,
        }) as u16
    }
    pub fn selector(self, prefix: u8, ports: (u16, u16), protocol: u8) -> Selector {
        let address = self.host("10.0.0.0", "fd00::");
        let ts = charon_kernel_daemon::model::Ts::from_subnet(
            address, prefix, protocol, ports.0, ports.1,
        )
        .unwrap();
        charon_kernel_daemon::backend::rpc_selector(ts)
    }
    pub fn sa(self, spi: u32) -> SaId {
        SaId {
            src: self.local(),
            dst: self.peer(),
            spi,
            protocol: libc::IPPROTO_ESP as u8,
            mark: Mark::default(),
            interface_id: 41,
        }
    }
    pub fn policy(self, direction: u32) -> PolicyId {
        PolicyId {
            direction,
            src: self.selector(0, (0, u16::MAX), 0),
            dst: self.selector(0, (0, u16::MAX), 0),
            mark: Mark::default(),
            interface_id: 41,
            interface: None,
            security_label: None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Cipher {
    Gcm,
    CbcSha256,
    CbcSha384,
    ChaCha,
}
impl Cipher {
    pub fn algorithms(self) -> (Algorithm, Algorithm) {
        use algorithms::{encryption as enc, integrity as auth};
        let (enc_id, enc_len, auth_id, auth_len) = match self {
            Self::Gcm => (enc::AES_GCM_ICV16, 20, auth::UNDEFINED, 0),
            Self::CbcSha256 => (enc::AES_CBC, 16, auth::HMAC_SHA2_256_128, 32),
            Self::CbcSha384 => (enc::AES_CBC, 16, auth::HMAC_SHA2_384_192, 48),
            Self::ChaCha => (enc::CHACHA20_POLY1305, 36, auth::UNDEFINED, 0),
        };
        (
            Algorithm {
                id: enc_id,
                name: String::new(),
                key: vec![0; enc_len],
            },
            Algorithm {
                id: auth_id,
                name: String::new(),
                key: vec![0; auth_len],
            },
        )
    }
}
pub fn sa_config(cipher: Cipher, inbound: bool, esn: bool) -> SaConfig {
    let (encryption, integrity) = cipher.algorithms();
    let limit = || LifetimeLimit {
        life: 0,
        rekey: 0,
        jitter: 0,
    };
    SaConfig {
        reqid: 42,
        acquire_sequence: 0,
        mode: mode::TUNNEL,
        src_selectors: None,
        dst_selectors: None,
        interface: None,
        encryption,
        integrity,
        lifetime: Some(Lifetime {
            time: limit(),
            bytes: limit(),
            packets: limit(),
        }),
        replay_window: 128,
        ipcomp: 0,
        cpi: 0,
        cpu: u32::MAX,
        hw_offload: 0,
        security_label: None,
        esn,
        udp_encapsulation: true,
        output_mark: Mark {
            value: 123,
            mask: u32::MAX,
        },
        tfc: 0,
        copy_df: true,
        copy_ecn: true,
        copy_dscp: 0,
        iptfs_dont_fragment: false,
        forward_icmp: false,
        initiator: false,
        inbound,
        update: false,
    }
}
pub fn policy_config(family: Family, spi: u32) -> PolicyConfig {
    PolicyConfig {
        kind: 1,
        priority: 1,
        manual_priority: 0,
        hw_offload: 0,
        pcpu_acquires: false,
        forward_icmp: false,
        src: Some(family.local()),
        dst: Some(family.peer()),
        sa: Some(PolicySa {
            mode: mode::TUNNEL,
            reqid: 42,
            policy_count: 2,
            esp: ProtocolSa { used: true, spi },
            ah: ProtocolSa {
                used: false,
                spi: 0,
            },
            ipcomp: CompressionSa {
                transform: 0,
                cpi: 0,
            },
        }),
    }
}

/// Production transport and generated client, with no intermediate encoding.
pub struct Rpc {
    pub kernel: KernelClient,
    pub notification: Notification,
    pub socket: UnixStream,
    runtime: Runtime,
}
impl Rpc {
    pub fn connect(path: &PathBuf) -> Self {
        let socket = UnixStream::connect(path).unwrap();
        let notification = Notification::receive(&socket).unwrap();
        socket.set_nonblocking(true).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let kernel = runtime.block_on(async {
            KernelClient::new(
                tarpc::client::Config::default(),
                transport::framed(
                    tokio::net::UnixStream::from_std(socket.try_clone().unwrap()).unwrap(),
                ),
            )
            .spawn()
        });
        Self {
            kernel,
            notification,
            socket,
            runtime,
        }
    }
    pub fn call<T>(
        &self,
        call: impl Future<Output = std::result::Result<Result<T>, RpcError>>,
    ) -> Result<T> {
        self.run(call).expect("RPC transport failed")
    }
    pub fn run<F: Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }
    pub fn open(&self, config: SessionConfig) {
        self.call(self.kernel.open_session(context::current(), config))
            .unwrap();
    }
    pub fn close(&self) {
        self.call(self.kernel.close_session(context::current()))
            .unwrap();
    }
    pub fn events(&self) -> Vec<Event> {
        self.call(self.kernel.next_events(context::current()))
            .unwrap()
    }
    pub fn expiries(&self, count: usize) -> Vec<Expiry> {
        let mut expiries = Vec::new();
        eventually(|| {
            expiries.extend(self.events().into_iter().filter_map(|event| event.expiry));
            expiries.len() >= count
        });
        assert_eq!(expiries.len(), count);
        expiries
    }
}
impl Drop for Rpc {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(Shutdown::Both);
    }
}

pub struct Daemon {
    pub process: Child,
    pub path: PathBuf,
    directory: tempfile::TempDir,
}
impl Daemon {
    pub fn start(args: &[&str]) -> Self {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let path = directory.path().join("kernel.sock");
        let log = File::create(directory.path().join("daemon.log")).unwrap();
        let process = Command::new(env!("CARGO_BIN_EXE_charon-kernel-daemon"))
            .arg("--socket")
            .arg(&path)
            .args(args)
            .env_remove("NOTIFY_SOCKET")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(log)
            .spawn()
            .unwrap();
        let mut daemon = Self {
            process,
            path,
            directory,
        };
        eventually(|| {
            assert!(
                daemon.process.try_wait().unwrap().is_none(),
                "daemon exited during startup: {}",
                daemon.log()
            );
            daemon.path.exists()
        });
        daemon
    }
    pub fn connect(&self) -> Rpc {
        Rpc::connect(&self.path)
    }
    pub fn session(&self) -> Rpc {
        let rpc = self.connect();
        rpc.open(SessionConfig::default());
        rpc
    }
    pub fn signal(&self, signal: Signal) {
        kill(Pid::from_raw(self.process.id() as i32), signal).unwrap();
    }
    pub fn wait(&mut self) -> ExitStatus {
        let mut status = None;
        eventually(|| {
            status = self.process.try_wait().unwrap();
            status.is_some()
        });
        status.unwrap()
    }
    fn log(&self) -> String {
        fs::read_to_string(self.directory.path().join("daemon.log")).unwrap()
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        if self.process.try_wait().unwrap().is_none() {
            let _ = self.process.kill();
            let _ = self.process.wait();
        }
        if thread::panicking() {
            eprintln!("daemon log:\n{}", self.log());
        }
    }
}
