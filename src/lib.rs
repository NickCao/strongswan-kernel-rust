// SPDX-License-Identifier: GPL-2.0-or-later
//! The privileged half of strongSwan's kernel-rust backend.
//!
//! RPC messages contain semantic operations, never caller-supplied Netlink
//! messages. Linux UAPI structures are encoded in zero-initialized buffers;
//! no Rust padding or pointers are transmitted to the kernel or the client.
#![forbid(unsafe_code)]

pub mod backend;
pub mod error;
pub mod interfaces;
pub mod linux;
pub mod model;
pub mod policy;
pub mod transport;
pub use kernel_rust_protocol as rpc_api;

pub mod service;
