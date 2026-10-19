// SPDX-License-Identifier: GPL-2.0-or-later
//! Ownership and value conversion at charon's C boundary.
use crate::{ffi, status_t_FAILED, Result};
use kernel_rust_protocol as api;
use std::{
    ffi::{CStr, CString},
    net::IpAddr,
    ptr::{self, NonNull},
    slice,
};

// SAFETY throughout this module: pointers are borrowed valid objects supplied
// by charon. Methods and chunks remain valid until the surrounding C call ends.
pub unsafe fn string(value: *const libc::c_char) -> Result<String> {
    if value.is_null() {
        return Err(status_t_FAILED);
    }
    unsafe { CStr::from_ptr(value) }
        .to_str()
        .map(str::to_owned)
        .map_err(|_| status_t_FAILED)
}

pub unsafe fn setting_str(key: &CStr, default: &CStr) -> Result<String> {
    unsafe {
        let settings = (*ffi::lib).settings;
        string((*settings).get_str.unwrap()(
            settings,
            key.as_ptr().cast_mut(),
            default.as_ptr().cast_mut(),
            (*ffi::lib).ns,
        ))
    }
}

pub unsafe fn setting_int(key: &CStr, default: i32) -> i32 {
    unsafe {
        let settings = (*ffi::lib).settings;
        (*settings).get_int.unwrap()(settings, key.as_ptr().cast_mut(), default, (*ffi::lib).ns)
    }
}

/// # Safety
/// The host library and its settings must be initialized for this call.
pub unsafe fn config() -> Result<kernel_rust_protocol::client::Config> {
    let default = CString::new(env!("KERNEL_RUST_SOCKET")).map_err(|_| status_t_FAILED)?;
    unsafe {
        Ok(kernel_rust_protocol::client::Config {
            path: setting_str(c"%s.plugins.kernel-rust.socket", &default)?,
            daemon_uid: setting_int(c"%s.plugins.kernel-rust.daemon_uid", 0) as u32,
            interfaces_use: setting_str(c"%s.interfaces_use", c"")?,
            interfaces_ignore: setting_str(c"%s.interfaces_ignore", c"")?,
        })
    }
}

unsafe fn address(chunk: ffi::chunk_t) -> Result<IpAddr> {
    // SAFETY: the caller borrows this chunk from a live C host/selector.
    let bytes = unsafe { chunk_bytes(chunk) }?;
    match bytes.len() {
        4 => Ok(IpAddr::from(<[u8; 4]>::try_from(bytes).unwrap())),
        16 => Ok(IpAddr::from(<[u8; 16]>::try_from(bytes).unwrap())),
        _ => Err(status_t_FAILED),
    }
}

/// # Safety
/// Nonempty chunks must be valid and immutable for the returned borrow.
unsafe fn chunk_bytes<'a>(chunk: ffi::chunk_t) -> Result<&'a [u8]> {
    if chunk.len == 0 {
        return Ok(&[]);
    }
    if chunk.ptr.is_null() || chunk.len > isize::MAX as usize {
        return Err(status_t_FAILED);
    }
    // SAFETY: supplied by the C object for this callback's duration. Check the
    // slice's length/null constraints here; the C caller guarantees its storage.
    Ok(unsafe { slice::from_raw_parts(chunk.ptr, chunk.len) })
}

pub unsafe fn endpoint(host: *mut ffi::host_t) -> Result<api::Endpoint> {
    if host.is_null() {
        return Err(status_t_FAILED);
    }
    let (address, port) = unsafe {
        (
            address((*host).get_address.unwrap()(host))?,
            (*host).get_port.unwrap()(host),
        )
    };
    Ok(api::Endpoint {
        address: address.to_string(),
        port: port.into(),
    })
}

pub unsafe fn optional_endpoint(host: *mut ffi::host_t) -> Result<Option<api::Endpoint>> {
    if host.is_null() {
        Ok(None)
    } else {
        unsafe { endpoint(host) }.map(Some)
    }
}

// Private handles prevent safe Rust from constructing an invalid owning object
// or changing its pointer. Each successful C constructor has exactly one owner.
pub struct Host(NonNull<ffi::host_t>);
impl Host {
    pub fn parse(value: &api::Endpoint) -> Result<Self> {
        // Numeric addresses only: never pass a remote string to the resolver.
        let address: IpAddr = value.address.parse().map_err(|_| status_t_FAILED)?;
        let port = u16::try_from(value.port).map_err(|_| status_t_FAILED)?;
        let text = CString::new(address.to_string()).map_err(|_| status_t_FAILED)?;
        let host = unsafe { ffi::host_create_from_string(text.as_ptr().cast_mut(), port) };
        NonNull::new(host).map(Self).ok_or(status_t_FAILED)
    }
    pub fn as_raw(&self) -> *mut ffi::host_t {
        self.0.as_ptr()
    }
    pub fn family(&self) -> i32 {
        // SAFETY: this handle owns a live host made by its C constructor.
        unsafe { (*self.as_raw()).get_family.unwrap()(self.as_raw()) }
    }
    pub fn into_raw(self) -> *mut ffi::host_t {
        let raw = self.as_raw();
        std::mem::forget(self);
        raw
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        // SAFETY: only parse() can construct this owning handle.
        unsafe { (*self.as_raw()).destroy.unwrap()(self.as_raw()) }
    }
}

pub unsafe fn selector(ts: *mut ffi::traffic_selector_t) -> Result<api::Selector> {
    if ts.is_null() {
        return Err(status_t_FAILED);
    }
    let (from, to, protocol, first, last) = unsafe {
        (
            address((*ts).get_from_address.unwrap()(ts))?,
            address((*ts).get_to_address.unwrap()(ts))?,
            (*ts).get_protocol.unwrap()(ts),
            (*ts).get_from_port.unwrap()(ts),
            (*ts).get_to_port.unwrap()(ts),
        )
    };
    if from.is_ipv4() != to.is_ipv4() {
        return Err(status_t_FAILED);
    }
    Ok(api::Selector {
        from: from.to_string(),
        to: to.to_string(),
        protocol: protocol.into(),
        fromPort: first.into(),
        toPort: last.into(),
    })
}

pub struct Selector(NonNull<ffi::traffic_selector_t>);
impl Selector {
    pub fn as_raw(&self) -> *mut ffi::traffic_selector_t {
        self.0.as_ptr()
    }
    pub fn parse(value: &api::Selector) -> Result<Self> {
        let from = Host::parse(&api::Endpoint {
            address: value.from.clone(),
            port: 0,
        })?;
        let to = Host::parse(&api::Endpoint {
            address: value.to.clone(),
            port: 0,
        })?;
        let protocol = u8::try_from(value.protocol).map_err(|_| status_t_FAILED)?;
        let first = u16::try_from(value.fromPort).map_err(|_| status_t_FAILED)?;
        let last = u16::try_from(value.toPort).map_err(|_| status_t_FAILED)?;
        if first > last {
            return Err(status_t_FAILED);
        }
        let family = from.family();
        if family != to.family() {
            return Err(status_t_FAILED);
        }
        let kind = if family == libc::AF_INET {
            ffi::ts_type_t_TS_IPV4_ADDR_RANGE
        } else {
            ffi::ts_type_t_TS_IPV6_ADDR_RANGE
        };
        // SAFETY: both hosts are private owning handles that stay alive for
        // this call. The C selector constructor copies their address chunks.
        unsafe {
            let ts = ffi::traffic_selector_create_from_bytes(
                protocol,
                kind,
                (*from.as_raw()).get_address.unwrap()(from.as_raw()),
                first,
                (*to.as_raw()).get_address.unwrap()(to.as_raw()),
                last,
            );
            NonNull::new(ts).map(Self).ok_or(status_t_FAILED)
        }
    }
}
impl Drop for Selector {
    fn drop(&mut self) {
        // SAFETY: only parse() can construct this owning handle.
        unsafe { (*self.as_raw()).destroy.unwrap()(self.as_raw()) }
    }
}

pub fn mark(value: ffi::mark_t) -> api::Mark {
    api::Mark {
        value: value.value.into(),
        mask: value.mask.into(),
    }
}

// Returned names are allocated by libc: charon releases them with free().
pub fn duplicate(value: &str) -> Result<*mut libc::c_char> {
    let text = CString::new(value).map_err(|_| status_t_FAILED)?;
    let copy = unsafe { libc::strdup(text.as_ptr()) };
    if copy.is_null() {
        Err(status_t_FAILED)
    } else {
        Ok(copy)
    }
}

pub unsafe fn unrestricted_interface(value: *const libc::c_char) -> bool {
    value.is_null() || unsafe { *value == 0 }
}

pub unsafe fn algorithm(
    id: u16,
    key: ffi::chunk_t,
    kind: ffi::transform_type_t,
) -> Result<api::Algorithm> {
    if key.len > 8192 || (key.len != 0 && key.ptr.is_null()) {
        return Err(status_t_FAILED);
    }
    let mut name = ptr::null_mut();
    // SAFETY: the C callback keeps the host kernel interface alive.
    unsafe {
        let kernel = (*ffi::charon).kernel;
        (*kernel).lookup_algorithm.unwrap()(kernel, id, kind, ptr::null_mut(), &mut name);
    }
    let name = if name.is_null() {
        String::new()
    } else {
        unsafe { string(name) }?
    };
    let bytes = unsafe { chunk_bytes(key) }?;
    let mut hex = String::with_capacity(key.len * 2);
    const DIGITS: &[u8] = b"0123456789abcdef";
    for byte in bytes {
        hex.push(DIGITS[(byte >> 4) as usize] as char);
        hex.push(DIGITS[(byte & 15) as usize] as char);
    }
    Ok(api::Algorithm {
        id: id.into(),
        name,
        key: hex,
    })
}
