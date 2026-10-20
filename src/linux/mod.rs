// SPDX-License-Identifier: GPL-2.0-or-later
//! Linux device backends and their Netlink support. Desired state and
//! reconciliation controllers live in the platform-independent modules.

pub mod interfaces;
pub mod netlink;
pub mod network;
pub mod policy;
pub mod xfrm;
