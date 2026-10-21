// SPDX-License-Identifier: GPL-2.0-or-later
//! Ownership and value conversion at charon's C boundary.
use crate::{ffi, status_t_FAILED, Result};
use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};
use kernel_rust_protocol as api;
use std::{
    ffi::{CStr, CString},
    net::{IpAddr, SocketAddr},
    ptr, slice,
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

pub unsafe fn optional_string(value: *const libc::c_char) -> Result<Option<String>> {
    if value.is_null() {
        Ok(None)
    } else {
        unsafe { string(value) }.map(Some)
    }
}

pub unsafe fn label(value: *mut ffi::sec_label_t) -> Result<Option<Vec<u8>>> {
    if value.is_null() {
        return Ok(None);
    }
    let bytes = unsafe { chunk_bytes((*value).get_encoding.unwrap()(value)) }?;
    Ok(Some(bytes.to_vec()))
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
    unsafe {
        Ok(kernel_rust_protocol::client::Config {
            path: setting_str(
                c"%s.plugins.kernel-rust.socket",
                c"/run/charon-kernel/charon-kernel.sock",
            )?,
            session: api::SessionConfig {
                interfaces_use: setting_str(c"%s.interfaces_use", c"")?,
                interfaces_ignore: setting_str(c"%s.interfaces_ignore", c"")?,
            },
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
    // SAFETY: borrow the caller's live host for this conversion only.
    unsafe { HostRef::from_ptr(host) }.to_endpoint()
}

pub unsafe fn optional_endpoint(host: *mut ffi::host_t) -> Result<Option<api::Endpoint>> {
    if host.is_null() {
        Ok(None)
    } else {
        unsafe { endpoint(host) }.map(Some)
    }
}

foreign_type! {
    // SAFETY: successful C constructors transfer ownership to these wrappers.
    // Their destructors match those constructors; borrowed refs never own them.
    pub unsafe type Host {
        type CType = ffi::host_t;
        fn drop = destroy_host;
    }

    pub unsafe type Selector {
        type CType = ffi::traffic_selector_t;
        fn drop = destroy_selector;
    }

    pub unsafe type Enumerator {
        type CType = ffi::enumerator_t;
        fn drop = destroy_enumerator;
    }
}

unsafe fn destroy_host(host: *mut ffi::host_t) {
    // SAFETY: called once by the owning wrapper while the host library is live.
    unsafe { (*host).destroy.unwrap()(host) }
}

unsafe fn destroy_selector(selector: *mut ffi::traffic_selector_t) {
    // SAFETY: called once by the owning wrapper while the host library is live.
    unsafe { (*selector).destroy.unwrap()(selector) }
}

unsafe fn destroy_enumerator(enumerator: *mut ffi::enumerator_t) {
    unsafe { (*enumerator).destroy.unwrap()(enumerator) }
}

impl Host {
    pub fn parse(value: &api::Endpoint) -> Result<Self> {
        let address = SocketAddr::try_from(value).map_err(|_| status_t_FAILED)?;
        let native = rustix::net::SocketAddrAny::from(address);
        // SAFETY: the C constructor copies the complete initialized sockaddr.
        let host = unsafe { ffi::host_create_from_sockaddr(native.as_ptr().cast_mut().cast()) };
        if host.is_null() {
            return Err(status_t_FAILED);
        }
        // SAFETY: the constructor returned a live, uniquely owned host.
        Ok(unsafe { Self::from_ptr(host) })
    }
}

impl HostRef {
    pub fn family(&self) -> i32 {
        let host = self.as_ptr();
        // SAFETY: owned and borrowed wrappers both refer to live C hosts.
        unsafe { (*host).get_family.unwrap()(host) }
    }
    fn to_endpoint(&self) -> Result<api::Endpoint> {
        let host = self.as_ptr();
        // SAFETY: charon's live host owns the sockaddr and its initialized
        // length for this borrow. Read it whole, including IPv6 flow/scope.
        let native = unsafe {
            rustix::net::SocketAddrAny::read(
                (*host).get_sockaddr.unwrap()(host).cast(),
                *(*host).get_sockaddr_len.unwrap()(host),
            )
        };
        SocketAddr::try_from(native)
            .map(api::Endpoint::from)
            .map_err(|_| status_t_FAILED)
    }
}

pub unsafe fn selector(ts: *mut ffi::traffic_selector_t) -> Result<api::Selector> {
    if ts.is_null() {
        return Err(status_t_FAILED);
    }
    // SAFETY: borrow the caller's live selector for this conversion only.
    unsafe { SelectorRef::from_ptr(ts) }.to_selector()
}

pub unsafe fn selectors(list: *mut ffi::linked_list_t) -> Result<Option<Vec<api::Selector>>> {
    if list.is_null() {
        return Ok(None);
    }
    let raw = unsafe { (*list).create_enumerator.unwrap()(list) };
    if raw.is_null() {
        return Err(status_t_FAILED);
    }
    // SAFETY: the C list lends its elements while we own its enumerator. The
    // wrapper also destroys the enumerator if converting an element fails.
    let enumerator = unsafe { Enumerator::from_ptr(raw) };
    let mut values = Vec::new();
    loop {
        let mut value: *mut ffi::traffic_selector_t = ptr::null_mut();
        if !unsafe { (*raw).enumerate.unwrap()(raw, &mut value) } {
            break;
        }
        values.push(unsafe { selector(value) }?);
    }
    drop(enumerator);
    Ok(Some(values))
}

impl Selector {
    pub fn parse(value: &api::Selector) -> Result<Self> {
        let from = Host::parse(&api::Endpoint {
            address: value.from,
            port: 0,
            flow_info: 0,
            scope_id: 0,
        })?;
        let to = Host::parse(&api::Endpoint {
            address: value.to,
            port: 0,
            flow_info: 0,
            scope_id: 0,
        })?;
        let protocol = value.protocol;
        let first = value.from_port;
        let last = value.to_port;
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
        let ts = unsafe {
            ffi::traffic_selector_create_from_bytes(
                protocol,
                kind,
                (*from.as_ptr()).get_address.unwrap()(from.as_ptr()),
                first,
                (*to.as_ptr()).get_address.unwrap()(to.as_ptr()),
                last,
            )
        };
        if ts.is_null() {
            return Err(status_t_FAILED);
        }
        // SAFETY: the constructor returned a live, uniquely owned selector.
        Ok(unsafe { Self::from_ptr(ts) })
    }
}

impl SelectorRef {
    fn to_selector(&self) -> Result<api::Selector> {
        let ts = self.as_ptr();
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
            kind: unsafe { (*ts).get_type.unwrap()(ts) },
            dynamic: unsafe { (*ts).is_dynamic.unwrap()(ts) },
            from,
            to,
            protocol,
            from_port: first,
            to_port: last,
        })
    }
}

pub fn mark(value: ffi::mark_t) -> api::Mark {
    api::Mark {
        value: value.value,
        mask: value.mask,
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

pub unsafe fn algorithm(
    id: u16,
    key: ffi::chunk_t,
    kind: ffi::transform_type_t,
) -> Result<api::Algorithm> {
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
    Ok(api::Algorithm {
        id,
        name,
        key: bytes.to_vec(),
    })
}
