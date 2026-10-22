// SPDX-License-Identifier: GPL-2.0-or-later
//! Shared Rust RPC contract. Values preserve strongSwan's complete kernel
//! inputs; capability checks belong to the daemon, not the C adapter.
#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr};
pub use tarpc::{client::RpcError, context};

pub mod algorithms;
pub mod client;
mod endpoint;
mod enums;
mod flags;
pub mod notification;
pub mod transport;

pub use algorithms::{EncryptionAlgorithm, IntegrityAlgorithm};
pub use enums::{
    DscpCopy, HwOffload, IpcompTransform, IpsecMode, PolicyDirection, PolicyKind, PolicyPriority,
    SelectorKind,
};
pub use flags::{AddressTypes, KernelFeatures};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Error {
    Kernel(i32),
    AccessDenied,
    SessionBusy,
    InvalidSession,
}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Kernel(error.raw_os_error().unwrap_or(22))
    }
}
impl fmt::Display for Error {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "{self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionConfig {
    pub interfaces_use: String,
    pub interfaces_ignore: String,
    #[serde(default)]
    pub iptfs: IptfsConfig,
}

/// charon.iptfs settings. Times are microseconds; queue/packet sizes are bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IptfsConfig {
    pub drop_time: u32,
    pub reorder_window: u16,
    pub init_delay: u32,
    pub max_queue_size: u32,
    pub packet_size: u32,
    pub dont_fragment: bool,
}
impl Default for IptfsConfig {
    fn default() -> Self {
        // Defaults used by strongSwan's kernel-netlink backend.
        Self {
            drop_time: 1_000_000,
            reorder_window: 3,
            init_delay: 0,
            max_queue_size: 1024 * 1024,
            packet_size: 0,
            dont_fragment: false,
        }
    }
}
impl SessionConfig {
    pub fn usable(&self, interface: &str) -> bool {
        let member = |list: &str| list.split(',').any(|entry| entry.trim() == interface);
        if !self.interfaces_use.is_empty() {
            member(&self.interfaces_use)
        } else {
            !member(&self.interfaces_ignore)
        }
    }
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub features: KernelFeatures,
}

// SocketAddr's Serde representation drops IPv6 sockaddr metadata. Preserve
// these explicit, typed fields instead of serializing its display string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: u16,
    #[serde(default)]
    pub flow_info: u32,
    #[serde(default)]
    pub scope_id: u32,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Mark {
    pub value: u32,
    pub mask: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Selector {
    pub kind: SelectorKind,
    pub dynamic: bool,
    pub from: IpAddr,
    pub to: IpAddr,
    pub protocol: u8,
    pub from_port: u16,
    pub to_port: u16,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaId {
    pub src: Endpoint,
    pub dst: Endpoint,
    pub spi: u32,
    pub protocol: u8,
    pub mark: Mark,
    pub interface_id: u32,
}
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct Algorithm<Id> {
    pub id: Id,
    pub name: String,
    pub key: Vec<u8>,
}
impl<Id: fmt::Debug> fmt::Debug for Algorithm<Id> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("Algorithm")
            .field("id", &self.id)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}
impl<Id> Drop for Algorithm<Id> {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
    }
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifetimeLimit {
    pub life: u64,
    pub rekey: u64,
    pub jitter: u64,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lifetime {
    pub time: LifetimeLimit,
    pub bytes: LifetimeLimit,
    pub packets: LifetimeLimit,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaConfig {
    pub reqid: u32,
    pub acquire_sequence: u32,
    pub mode: IpsecMode,
    pub src_selectors: Option<Vec<Selector>>,
    pub dst_selectors: Option<Vec<Selector>>,
    pub interface: Option<String>,
    pub encryption: Algorithm<EncryptionAlgorithm>,
    pub integrity: Algorithm<IntegrityAlgorithm>,
    pub lifetime: Option<Lifetime>,
    pub replay_window: u32,
    pub ipcomp: IpcompTransform,
    pub cpi: u16,
    pub cpu: u32,
    pub hw_offload: HwOffload,
    pub security_label: Option<Vec<u8>>,
    pub esn: bool,
    pub udp_encapsulation: bool,
    pub output_mark: Mark,
    pub tfc: u32,
    pub copy_df: bool,
    pub copy_ecn: bool,
    pub copy_dscp: DscpCopy,
    pub iptfs_dont_fragment: bool,
    pub forward_icmp: bool,
    pub initiator: bool,
    pub inbound: bool,
    pub update: bool,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaUpdate {
    pub mode: IpsecMode,
    pub cpi: u16,
    pub src: Endpoint,
    pub dst: Endpoint,
    pub udp_encapsulation: bool,
    pub new_udp_encapsulation: bool,
    pub old_reqid: u32,
    pub new_reqid: u32,
    pub hw_offload: HwOffload,
    pub src_selectors: Option<Vec<Selector>>,
    pub dst_selectors: Option<Vec<Selector>>,
    pub interface: Option<String>,
    pub inbound: bool,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaUsage {
    pub bytes: u64,
    pub packets: u64,
    /// Last use in monotonic seconds, or zero if unused/unavailable.
    pub last_use: u64,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyId {
    pub direction: PolicyDirection,
    pub src: Selector,
    pub dst: Selector,
    pub mark: Mark,
    pub interface_id: u32,
    pub interface: Option<String>,
    pub security_label: Option<Vec<u8>>,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolSa {
    pub used: bool,
    pub spi: u32,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionSa {
    pub transform: IpcompTransform,
    pub cpi: u16,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySa {
    pub mode: IpsecMode,
    pub reqid: u32,
    pub policy_count: u32,
    pub esp: ProtocolSa,
    pub ah: ProtocolSa,
    pub ipcomp: CompressionSa,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub kind: PolicyKind,
    pub priority: PolicyPriority,
    pub manual_priority: u32,
    pub hw_offload: HwOffload,
    pub pcpu_acquires: bool,
    pub forward_icmp: bool,
    pub src: Option<Endpoint>,
    pub dst: Option<Endpoint>,
    pub sa: Option<PolicySa>,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subnet {
    pub address: Endpoint,
    pub prefix: u8,
    pub interface: String,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NextHop {
    pub gateway: Endpoint,
    pub interface: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Expiry {
    pub protocol: u8,
    pub spi: u32,
    pub destination: Endpoint,
    pub hard: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acquire {
    pub reqid: u32,
    pub src: Selector,
    pub dst: Selector,
    pub sequence: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mapping {
    pub spi: u32,
    pub destination: Endpoint,
    pub remote: Endpoint,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    Expire,
    Acquire,
    Mapping,
    Roam,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub kind: EventKind,
    pub expiry: Option<Expiry>,
    pub acquire: Option<Acquire>,
    pub mapping: Option<Mapping>,
    pub address_changed: Option<bool>,
}

#[tarpc::service]
pub trait Kernel {
    async fn open_session(config: SessionConfig) -> Result<SessionInfo>;
    async fn close_session() -> Result<()>;
    // Drain one queued batch, returning an empty batch when idle.
    async fn next_events() -> Result<Vec<Event>>;
    async fn allocate_spi(
        src: Endpoint,
        dst: Endpoint,
        protocol: u8,
        minimum: u32,
        maximum: u32,
    ) -> Result<u32>;
    async fn allocate_cpi(src: Endpoint, dst: Endpoint) -> Result<u16>;
    async fn install_sa(id: SaId, config: SaConfig) -> Result<()>;
    async fn update_sa(id: SaId, config: SaUpdate) -> Result<()>;
    async fn query_sa(id: SaId, cpi: u16) -> Result<SaUsage>;
    async fn remove_sa(id: SaId, cpi: u16) -> Result<()>;
    async fn flush_sas() -> Result<()>;
    async fn install_policy(id: PolicyId, config: PolicyConfig) -> Result<()>;
    async fn query_policy(id: PolicyId) -> Result<u64>;
    async fn remove_policy(id: PolicyId, config: PolicyConfig) -> Result<()>;
    async fn flush_policies() -> Result<()>;
    async fn bypass_port(family: u16, port: u16) -> Result<()>;
    async fn get_source_address(
        destination: Endpoint,
        source: Option<Endpoint>,
    ) -> Result<Endpoint>;
    async fn get_next_hop(
        destination: Endpoint,
        source: Option<Endpoint>,
        prefix: Option<i32>,
    ) -> Result<NextHop>;
    async fn get_interface(address: Endpoint) -> Result<String>;
    async fn list_addresses(which: AddressTypes) -> Result<Vec<Endpoint>>;
    async fn list_subnets() -> Result<Vec<Subnet>>;
}
