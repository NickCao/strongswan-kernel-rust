// SPDX-License-Identifier: GPL-2.0-or-later
//! Ownership and value conversion at charon's C boundary.
use crate::{ffi, status_t_FAILED, Result};
use kernel_rust_protocol as api;
use std::{
    ffi::{CStr, CString},
    net::IpAddr,
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

unsafe fn address(chunk: ffi::chunk_t) -> Result<IpAddr> {
    if chunk.ptr.is_null() {
        return Err(status_t_FAILED);
    }
    unsafe {
        match chunk.len {
            4 => Ok(IpAddr::from(
                <[u8; 4]>::try_from(slice::from_raw_parts(chunk.ptr, 4)).unwrap(),
            )),
            16 => Ok(IpAddr::from(
                <[u8; 16]>::try_from(slice::from_raw_parts(chunk.ptr, 16)).unwrap(),
            )),
            _ => Err(status_t_FAILED),
        }
    }
}

pub unsafe fn endpoint(host: *mut ffi::host_t) -> Result<api::Endpoint> {
    if host.is_null() {
        return Err(status_t_FAILED);
    }
    unsafe {
        Ok(api::Endpoint {
            address: address((*host).get_address.unwrap()(host))?.to_string(),
            port: (*host).get_port.unwrap()(host).into(),
        })
    }
}

pub unsafe fn optional_endpoint(host: *mut ffi::host_t) -> Result<Option<api::Endpoint>> {
    if host.is_null() {
        Ok(None)
    } else {
        unsafe { endpoint(host) }.map(Some)
    }
}

pub struct Host(pub *mut ffi::host_t);
impl Host {
    pub fn parse(value: &api::Endpoint) -> Result<Self> {
        // Numeric addresses only: never pass a remote string to the resolver.
        let address: IpAddr = value.address.parse().map_err(|_| status_t_FAILED)?;
        let port = u16::try_from(value.port).map_err(|_| status_t_FAILED)?;
        let text = CString::new(address.to_string()).map_err(|_| status_t_FAILED)?;
        let host = unsafe { ffi::host_create_from_string(text.as_ptr().cast_mut(), port) };
        if host.is_null() {
            Err(status_t_FAILED)
        } else {
            Ok(Self(host))
        }
    }
    pub fn into_raw(self) -> *mut ffi::host_t {
        let raw = self.0;
        std::mem::forget(self);
        raw
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        unsafe { (*self.0).destroy.unwrap()(self.0) }
    }
}

pub unsafe fn selector(ts: *mut ffi::traffic_selector_t) -> Result<api::Selector> {
    if ts.is_null() {
        return Err(status_t_FAILED);
    }
    unsafe {
        let from = address((*ts).get_from_address.unwrap()(ts))?;
        let to = address((*ts).get_to_address.unwrap()(ts))?;
        if from.is_ipv4() != to.is_ipv4() {
            return Err(status_t_FAILED);
        }
        Ok(api::Selector {
            from: from.to_string(),
            to: to.to_string(),
            protocol: (*ts).get_protocol.unwrap()(ts).into(),
            fromPort: (*ts).get_from_port.unwrap()(ts).into(),
            toPort: (*ts).get_to_port.unwrap()(ts).into(),
        })
    }
}

pub struct Selector(pub *mut ffi::traffic_selector_t);
impl Selector {
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
        unsafe {
            let family = (*from.0).get_family.unwrap()(from.0);
            if family != (*to.0).get_family.unwrap()(to.0) {
                return Err(status_t_FAILED);
            }
            let kind = if family == libc::AF_INET {
                ffi::ts_type_t_TS_IPV4_ADDR_RANGE
            } else {
                ffi::ts_type_t_TS_IPV6_ADDR_RANGE
            };
            let ts = ffi::traffic_selector_create_from_bytes(
                protocol,
                kind,
                (*from.0).get_address.unwrap()(from.0),
                first,
                (*to.0).get_address.unwrap()(to.0),
                last,
            );
            if ts.is_null() {
                Err(status_t_FAILED)
            } else {
                Ok(Self(ts))
            }
        }
    }
}
impl Drop for Selector {
    fn drop(&mut self) {
        unsafe { (*self.0).destroy.unwrap()(self.0) }
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
    unsafe {
        let kernel = (*ffi::charon).kernel;
        let mut name = ptr::null_mut();
        (*kernel).lookup_algorithm.unwrap()(kernel, id, kind, ptr::null_mut(), &mut name);
        let name = if name.is_null() {
            String::new()
        } else {
            string(name)?
        };
        let mut hex = String::with_capacity(key.len * 2);
        const DIGITS: &[u8] = b"0123456789abcdef";
        if key.len != 0 {
            for byte in slice::from_raw_parts(key.ptr, key.len) {
                hex.push(DIGITS[(byte >> 4) as usize] as char);
                hex.push(DIGITS[(byte & 15) as usize] as char);
            }
        }
        Ok(api::Algorithm {
            id: id.into(),
            name,
            key: hex,
        })
    }
}
