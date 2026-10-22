// SPDX-License-Identifier: GPL-2.0-or-later
//! Shared numeric enums. Unknown values cross RPC without being discarded.
use num_enum::{FromPrimitive, IntoPrimitive};
use serde::{Deserialize, Serialize};

/// strongSwan IPsec modes, distinct from Linux XFRM mode numbers.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, FromPrimitive, IntoPrimitive, Serialize, Deserialize,
)]
#[repr(u32)]
#[serde(from = "u32", into = "u32")]
pub enum IpsecMode {
    None = 0,
    Transport = 1,
    Tunnel = 2,
    Beet = 3,
    Pass = 4,
    Drop = 5,
    Iptfs = 6,
    #[num_enum(catch_all)]
    Other(u32),
}

/// strongSwan traffic selector types.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, FromPrimitive, IntoPrimitive, Serialize, Deserialize,
)]
#[repr(u32)]
#[serde(from = "u32", into = "u32")]
pub enum SelectorKind {
    Ipv4Range = 7,
    Ipv6Range = 8,
    SecurityLabel = 10,
    #[num_enum(catch_all)]
    Other(u32),
}

/// strongSwan policy directions.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, FromPrimitive, IntoPrimitive, Serialize, Deserialize,
)]
#[repr(u32)]
#[serde(from = "u32", into = "u32")]
pub enum PolicyDirection {
    Inbound = 0,
    Outbound = 1,
    Forward = 2,
    #[num_enum(catch_all)]
    Other(u32),
}

/// strongSwan policy types.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, FromPrimitive, IntoPrimitive, Serialize, Deserialize,
)]
#[repr(u32)]
#[serde(from = "u32", into = "u32")]
pub enum PolicyKind {
    Ipsec = 1,
    Pass = 2,
    Drop = 3,
    #[num_enum(catch_all)]
    Other(u32),
}

/// strongSwan priority classes, separate from the computed kernel priority.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, FromPrimitive, IntoPrimitive, Serialize, Deserialize,
)]
#[repr(u32)]
#[serde(from = "u32", into = "u32")]
pub enum PolicyPriority {
    Pass = 0,
    Default = 1,
    Routed = 2,
    Fallback = 3,
    #[num_enum(catch_all)]
    Other(u32),
}

/// strongSwan hardware offload modes.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, FromPrimitive, IntoPrimitive, Serialize, Deserialize,
)]
#[repr(u32)]
#[serde(from = "u32", into = "u32")]
pub enum HwOffload {
    No = 0,
    Crypto = 1,
    Packet = 2,
    Auto = 3,
    #[num_enum(catch_all)]
    Other(u32),
}

/// strongSwan DSCP copying directions.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, FromPrimitive, IntoPrimitive, Serialize, Deserialize,
)]
#[repr(u32)]
#[serde(from = "u32", into = "u32")]
pub enum DscpCopy {
    OutOnly = 0,
    InOnly = 1,
    Yes = 2,
    No = 3,
    #[num_enum(catch_all)]
    Other(u32),
}

/// IPComp transform IDs as carried in strongSwan SA configuration.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, FromPrimitive, IntoPrimitive, Serialize, Deserialize,
)]
#[repr(u16)]
#[serde(from = "u16", into = "u16")]
pub enum IpcompTransform {
    None = 0,
    Oui = 1,
    Deflate = 2,
    Lzs = 3,
    Lzjh = 4,
    #[num_enum(catch_all)]
    Other(u16),
}
