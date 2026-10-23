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

pub async fn eventually(mut condition: impl std::ops::AsyncFnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition().await {
        assert!(
            Instant::now() < deadline,
            "condition did not converge within 10 seconds"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
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

pub async fn links() -> Vec<Link> {
    let mut network = Network::new().await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match network.links().await {
            // The daemon may change links during a dump. Discard the partial
            // inventory and observe again, as a later reconciliation would.
            Err(error)
                if error.kind() == std::io::ErrorKind::Interrupted && Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            result => return result.unwrap(),
        }
    }
}
pub async fn owned_links() -> Vec<Link> {
    links()
        .await
        .into_iter()
        .filter(|l| l.group == 17227)
        .collect()
}
pub async fn states() -> Vec<ModifyMessage> {
    Netlink::new(NlFamily::Xfrm)
        .await
        .unwrap()
        .request(&Message::new(
            XFRM_MSG_GETSA,
            NlmF::DUMP,
            &XfrmMessage::GetSa(Default::default()),
        ))
        .await
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
    pub fn policy(self, direction: PolicyDirection) -> PolicyId {
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
    pub fn algorithms(
        self,
    ) -> (
        Algorithm<EncryptionAlgorithm>,
        Algorithm<IntegrityAlgorithm>,
    ) {
        let (enc_id, enc_len, auth_id, auth_len) = match self {
            Self::Gcm => (
                EncryptionAlgorithm::AesGcmIcv16,
                20,
                IntegrityAlgorithm::Undefined,
                0,
            ),
            Self::CbcSha256 => (
                EncryptionAlgorithm::AesCbc,
                16,
                IntegrityAlgorithm::HmacSha256Icv128,
                32,
            ),
            Self::CbcSha384 => (
                EncryptionAlgorithm::AesCbc,
                16,
                IntegrityAlgorithm::HmacSha384Icv192,
                48,
            ),
            Self::ChaCha => (
                EncryptionAlgorithm::ChaCha20Poly1305,
                36,
                IntegrityAlgorithm::Undefined,
                0,
            ),
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
        mode: IpsecMode::Tunnel,
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
        ipcomp: IpcompTransform::None,
        cpi: 0,
        cpu: u32::MAX,
        hw_offload: HwOffload::No,
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
        copy_dscp: DscpCopy::OutOnly,
        iptfs_dont_fragment: false,
        forward_icmp: false,
        initiator: false,
        inbound,
        update: false,
    }
}
pub fn policy_config(family: Family, spi: u32) -> PolicyConfig {
    PolicyConfig {
        kind: PolicyKind::Ipsec,
        priority: PolicyPriority::Default,
        manual_priority: 0,
        hw_offload: HwOffload::No,
        pcpu_acquires: false,
        forward_icmp: false,
        src: Some(family.local()),
        dst: Some(family.peer()),
        sa: Some(PolicySa {
            mode: IpsecMode::Tunnel,
            reqid: 42,
            policy_count: 2,
            esp: ProtocolSa { used: true, spi },
            ah: ProtocolSa {
                used: false,
                spi: 0,
            },
            ipcomp: CompressionSa {
                transform: IpcompTransform::None,
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
}
impl Rpc {
    pub async fn connect(path: &PathBuf) -> Self {
        let socket = UnixStream::connect(path).unwrap();
        let notification = Notification::receive(&socket).unwrap();
        socket.set_nonblocking(true).unwrap();
        let kernel = KernelClient::new(
            tarpc::client::Config::default(),
            transport::framed(
                tokio::net::UnixStream::from_std(socket.try_clone().unwrap()).unwrap(),
            ),
        )
        .spawn();
        Self {
            kernel,
            notification,
            socket,
        }
    }
    pub async fn call<T>(
        &self,
        call: impl Future<Output = std::result::Result<Result<T>, RpcError>>,
    ) -> Result<T> {
        self.run(call).await.expect("RPC transport failed")
    }
    pub async fn run<F: Future>(&self, future: F) -> F::Output {
        future.await
    }
    pub async fn open(&self, config: SessionConfig) {
        self.call(self.kernel.open_session(context::current(), config))
            .await
            .unwrap();
    }
    pub async fn close(&self) {
        self.call(self.kernel.close_session(context::current()))
            .await
            .unwrap();
    }
    pub async fn events(&self) -> Vec<Event> {
        self.call(self.kernel.next_events(context::current()))
            .await
            .unwrap()
    }
    pub async fn expiries(&self, count: usize) -> Vec<Expiry> {
        let mut expiries = Vec::new();
        eventually(async || {
            expiries.extend(
                self.events()
                    .await
                    .into_iter()
                    .filter_map(|event| match event {
                        Event::Expire(expiry) => Some(expiry),
                        _ => None,
                    }),
            );
            expiries.len() >= count
        })
        .await;
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
        let deadline = Instant::now() + Duration::from_secs(10);
        while !daemon.path.exists() {
            assert!(
                daemon.process.try_wait().unwrap().is_none(),
                "daemon exited during startup: {}",
                daemon.log()
            );
            assert!(
                Instant::now() < deadline,
                "daemon did not create its socket"
            );
            thread::sleep(Duration::from_millis(20));
        }
        daemon
    }
    pub async fn connect(&self) -> Rpc {
        Rpc::connect(&self.path).await
    }
    pub async fn session(&self) -> Rpc {
        let rpc = self.connect().await;
        rpc.open(SessionConfig::default()).await;
        rpc
    }
    pub fn signal(&self, signal: Signal) {
        kill(Pid::from_raw(self.process.id() as i32), signal).unwrap();
    }
    pub async fn wait(&mut self) -> ExitStatus {
        let mut status = None;
        eventually(async || {
            status = self.process.try_wait().unwrap();
            status.is_some()
        })
        .await;
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
