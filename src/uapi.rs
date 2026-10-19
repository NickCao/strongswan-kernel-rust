// SPDX-License-Identifier: GPL-2.0-or-later
//! Linux XFRM UAPI layouts. Used only for size/offset calculation, never cast
//! to/from untrusted bytes. See src/include/linux/xfrm.h.
#![allow(dead_code)]
use std::mem::size_of;

#[repr(C)]
pub struct Address {
    pub words: [u32; 4],
}
#[repr(C)]
pub struct Id {
    pub daddr: Address,
    pub spi: u32,
    pub proto: u8,
}
#[repr(C)]
pub struct Selector {
    pub daddr: Address,
    pub saddr: Address,
    pub dport: u16,
    pub dport_mask: u16,
    pub sport: u16,
    pub sport_mask: u16,
    pub family: u16,
    pub prefixlen_d: u8,
    pub prefixlen_s: u8,
    pub proto: u8,
    pub ifindex: i32,
    pub user: u32,
}
#[repr(C)]
pub struct LifetimeCfg {
    pub values: [u64; 8],
}
#[repr(C)]
pub struct LifetimeCur {
    pub bytes: u64,
    pub packets: u64,
    pub add_time: u64,
    pub use_time: u64,
}
#[repr(C)]
pub struct Stats {
    pub replay_window: u32,
    pub replay: u32,
    pub integrity_failed: u32,
}
#[repr(C)]
pub struct Sa {
    pub sel: Selector,
    pub id: Id,
    pub saddr: Address,
    pub lft: LifetimeCfg,
    pub curlft: LifetimeCur,
    pub stats: Stats,
    pub seq: u32,
    pub reqid: u32,
    pub family: u16,
    pub mode: u8,
    pub replay_window: u8,
    pub flags: u8,
}
#[repr(C)]
pub struct SaId {
    pub daddr: Address,
    pub spi: u32,
    pub family: u16,
    pub proto: u8,
}
#[repr(C)]
pub struct Spi {
    pub info: Sa,
    pub min: u32,
    pub max: u32,
}
#[repr(C)]
pub struct Policy {
    pub sel: Selector,
    pub lft: LifetimeCfg,
    pub curlft: LifetimeCur,
    pub priority: u32,
    pub index: u32,
    pub dir: u8,
    pub action: u8,
    pub flags: u8,
    pub share: u8,
}
#[repr(C)]
pub struct PolicyId {
    pub sel: Selector,
    pub index: u32,
    pub dir: u8,
}
#[repr(C)]
pub struct Template {
    pub id: Id,
    pub family: u16,
    pub saddr: Address,
    pub reqid: u32,
    pub mode: u8,
    pub share: u8,
    pub optional: u8,
    pub aalgos: u32,
    pub ealgos: u32,
    pub calgos: u32,
}
#[repr(C)]
pub struct Acquire {
    pub id: Id,
    pub saddr: Address,
    pub sel: Selector,
    pub policy: Policy,
    pub aalgos: u32,
    pub ealgos: u32,
    pub calgos: u32,
    pub seq: u32,
}
#[repr(C)]
pub struct Expire {
    pub state: Sa,
    pub hard: u8,
}
#[repr(C)]
pub struct Mapping {
    pub id: SaId,
    pub reqid: u32,
    pub old_saddr: Address,
    pub new_saddr: Address,
    pub old_sport: u16,
    pub new_sport: u16,
}
#[repr(C)]
pub struct KmAddress {
    pub local: Address,
    pub remote: Address,
    pub reserved: u32,
    pub family: u16,
}
#[repr(C)]
pub struct Migrate {
    pub old_daddr: Address,
    pub old_saddr: Address,
    pub new_daddr: Address,
    pub new_saddr: Address,
    pub proto: u8,
    pub mode: u8,
    pub reserved: u16,
    pub reqid: u32,
    pub old_family: u16,
    pub new_family: u16,
}
#[repr(C)]
pub struct Encap {
    pub kind: u16,
    pub sport: u16,
    pub dport: u16,
    pub oa: Address,
}
#[repr(C)]
pub struct Offload {
    pub ifindex: i32,
    pub flags: u8,
}
#[repr(C)]
pub struct Aevent {
    pub id: SaId,
    pub saddr: Address,
    pub flags: u32,
    pub reqid: u32,
}

pub fn buffer<T>() -> Vec<u8> {
    vec![0; size_of::<T>()]
}
pub fn put16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_ne_bytes());
}
pub fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_ne_bytes());
}
pub fn put64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_ne_bytes());
}
pub fn get16(b: &[u8], o: usize) -> u16 {
    u16::from_ne_bytes(b[o..o + 2].try_into().unwrap())
}
pub fn get32(b: &[u8], o: usize) -> u32 {
    u32::from_ne_bytes(b[o..o + 4].try_into().unwrap())
}
pub fn get64(b: &[u8], o: usize) -> u64 {
    u64::from_ne_bytes(b[o..o + 8].try_into().unwrap())
}
