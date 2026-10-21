// SPDX-License-Identifier: GPL-2.0-or-later
//! Shared Rust RPC contract. Values preserve strongSwan's complete kernel
//! inputs; capability checks belong to the daemon, not the C adapter.
#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr};
pub use tarpc::{client::RpcError, context};

pub mod client;
mod endpoint;
pub mod notification;
pub mod transport;

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

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionConfig {
    pub interfaces_use: String,
    pub interfaces_ignore: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    pub features: u32,
}

// SocketAddr's Serde representation drops IPv6 sockaddr metadata. Preserve
// these explicit, typed fields instead of serializing its display string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: u16,
    #[serde(default)]
    pub flow_info: u32,
    #[serde(default)]
    pub scope_id: u32,
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Mark {
    pub value: u32,
    pub mask: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Selector {
    pub kind: i32,
    pub dynamic: bool,
    pub from: IpAddr,
    pub to: IpAddr,
    pub protocol: u8,
    pub from_port: u16,
    pub to_port: u16,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct SaId {
    pub src: Endpoint,
    pub dst: Endpoint,
    pub spi: u32,
    pub protocol: u8,
    pub mark: Mark,
    pub interface_id: u32,
}
#[derive(Serialize, Deserialize)]
pub struct Algorithm {
    pub id: u16,
    pub name: String,
    pub key: Vec<u8>,
}
impl fmt::Debug for Algorithm {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("Algorithm")
            .field("id", &self.id)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}
impl Drop for Algorithm {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct LifetimeLimit {
    pub life: u64,
    pub rekey: u64,
    pub jitter: u64,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Lifetime {
    pub time: LifetimeLimit,
    pub bytes: LifetimeLimit,
    pub packets: LifetimeLimit,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct SaConfig {
    pub reqid: u32,
    pub acquire_sequence: u32,
    pub mode: i32,
    pub src_selectors: Option<Vec<Selector>>,
    pub dst_selectors: Option<Vec<Selector>>,
    pub interface: Option<String>,
    pub encryption: Algorithm,
    pub integrity: Algorithm,
    pub lifetime: Option<Lifetime>,
    pub replay_window: u32,
    pub ipcomp: u16,
    pub cpi: u16,
    pub cpu: u32,
    pub hw_offload: i32,
    pub security_label: Option<Vec<u8>>,
    pub esn: bool,
    pub udp_encapsulation: bool,
    pub output_mark: Mark,
    pub tfc: u32,
    pub copy_df: bool,
    pub copy_ecn: bool,
    pub copy_dscp: i32,
    pub iptfs_dont_fragment: bool,
    pub forward_icmp: bool,
    pub initiator: bool,
    pub inbound: bool,
    pub update: bool,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct SaUpdate {
    pub mode: i32,
    pub cpi: u16,
    pub src: Endpoint,
    pub dst: Endpoint,
    pub udp_encapsulation: bool,
    pub new_udp_encapsulation: bool,
    pub old_reqid: u32,
    pub new_reqid: u32,
    pub hw_offload: i32,
    pub src_selectors: Option<Vec<Selector>>,
    pub dst_selectors: Option<Vec<Selector>>,
    pub interface: Option<String>,
    pub inbound: bool,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct SaUsage {
    pub bytes: u64,
    pub packets: u64,
    pub last_use: u64,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyId {
    pub direction: i32,
    pub src: Selector,
    pub dst: Selector,
    pub mark: Mark,
    pub interface_id: u32,
    pub interface: Option<String>,
    pub security_label: Option<Vec<u8>>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ProtocolSa {
    pub used: bool,
    pub spi: u32,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct CompressionSa {
    pub transform: u16,
    pub cpi: u16,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicySa {
    pub mode: i32,
    pub reqid: u32,
    pub policy_count: u32,
    pub esp: ProtocolSa,
    pub ah: ProtocolSa,
    pub ipcomp: CompressionSa,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub kind: i32,
    pub priority: i32,
    pub manual_priority: u32,
    pub hw_offload: i32,
    pub pcpu_acquires: bool,
    pub forward_icmp: bool,
    pub src: Option<Endpoint>,
    pub dst: Option<Endpoint>,
    pub sa: Option<PolicySa>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Subnet {
    pub address: Endpoint,
    pub prefix: u8,
    pub interface: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct NextHop {
    pub gateway: Endpoint,
    pub interface: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Expiry {
    pub protocol: u8,
    pub spi: u32,
    pub destination: Endpoint,
    pub hard: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Acquire {
    pub reqid: u32,
    pub src: Selector,
    pub dst: Selector,
    pub sequence: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Mapping {
    pub spi: u32,
    pub destination: Endpoint,
    pub remote: Endpoint,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EventKind {
    Expire,
    Acquire,
    Mapping,
    Roam,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    async fn list_addresses(which: i32) -> Result<Vec<Endpoint>>;
    async fn list_subnets() -> Result<Vec<Subnet>>;
}
