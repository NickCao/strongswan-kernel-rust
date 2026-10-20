// SPDX-License-Identifier: GPL-2.0-or-later
//! C ABI plugin loaded by an unprivileged charon. Kernel operations use tarpc.
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

mod events;
mod host;
mod ipsec;
mod net;
mod plugin;

use ffi::{status_t, status_t_FAILED, status_t_NOT_SUPPORTED, status_t_SUCCESS};
type Result<T> = std::result::Result<T, status_t>;

// Translate RPC errors only at the strongSwan adapter boundary.
trait ClientExt {
    fn call<T>(
        &self,
        future: impl std::future::Future<
            Output = std::result::Result<
                kernel_rust_protocol::Result<T>,
                kernel_rust_protocol::RpcError,
            >,
        >,
    ) -> Result<T>;
    fn empty(
        &self,
        future: impl std::future::Future<
            Output = std::result::Result<
                kernel_rust_protocol::Result<()>,
                kernel_rust_protocol::RpcError,
            >,
        >,
    ) -> status_t {
        self.call(future)
            .map_or_else(|status| status, |_| status_t_SUCCESS)
    }
}
impl ClientExt for kernel_rust_protocol::client::Client {
    fn call<T>(
        &self,
        future: impl std::future::Future<
            Output = std::result::Result<
                kernel_rust_protocol::Result<T>,
                kernel_rust_protocol::RpcError,
            >,
        >,
    ) -> Result<T> {
        self.request(future).map_err(|error| {
            log(&error.to_string());
            match error.errno {
                Some(libc::EEXIST) => ffi::status_t_ALREADY_DONE,
                Some(libc::ENOENT | libc::ESRCH) => ffi::status_t_NOT_FOUND,
                Some(libc::EOPNOTSUPP) => status_t_NOT_SUPPORTED,
                _ => status_t_FAILED,
            }
        })
    }
}

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
