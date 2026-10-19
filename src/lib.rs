// SPDX-License-Identifier: GPL-2.0-or-later
//! The privileged half of strongSwan's kernel-rust backend.
//!
//! RPC messages contain semantic operations, never caller-supplied Netlink
//! messages. Linux UAPI structures are encoded in zero-initialized buffers;
//! no Rust padding or pointers are transmitted to the kernel or the client.
pub mod backend;
pub mod error;
pub mod model;
pub mod netlink;
pub mod network;
pub mod transport;
pub mod uapi;
pub mod xfrm;
#[allow(clippy::all, non_snake_case, non_camel_case_types, dead_code)]
pub mod rpc_api {
    include!(concat!(env!("OUT_DIR"), "/kernel.rs"));
}

pub mod service;

// Wipe the typed input key strings as well as the decoded binary buffers.
impl Drop for rpc_api::Algorithm {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
    }
}
