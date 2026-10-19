// SPDX-License-Identifier: GPL-2.0-or-later
//! Shared, generated Varlink messages for the plugin and privileged daemon.
#![allow(clippy::all, non_snake_case, non_camel_case_types, dead_code)]
include!(concat!(env!("OUT_DIR"), "/kernel.rs"));
pub mod transport;

// Wipe the typed input key strings as well as decoded binary key buffers.
impl Drop for Algorithm {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
    }
}
