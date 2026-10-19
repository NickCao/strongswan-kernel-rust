// SPDX-License-Identifier: GPL-2.0-or-later
//! C ABI plugin loaded by an unprivileged charon. Kernel operations use Varlink.
#![deny(unsafe_op_in_unsafe_fn)]

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code,
    unnecessary_transmutes,
    clippy::all
)]
mod ffi {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

mod client;
mod host;
mod ipsec;
mod net;
mod plugin;

use ffi::{status_t, status_t_FAILED, status_t_NOT_SUPPORTED, status_t_SUCCESS};
type Result<T> = std::result::Result<T, status_t>;

fn log(message: &str) {
    if let Ok(message) = std::ffi::CString::new(message) {
        // The host initializes its logging hook before loading plugins.
        unsafe {
            if let Some(dbg) = ffi::dbg {
                dbg(
                    ffi::debug_t_DBG_KNL,
                    1,
                    c"kernel-rust: %s".as_ptr().cast_mut(),
                    message.as_ptr(),
                );
            }
        }
    }
}
