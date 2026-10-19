// SPDX-License-Identifier: GPL-2.0-or-later
use crate::{
    ffi,
    host::{self, Host},
    status_t, status_t_FAILED, status_t_NOT_SUPPORTED, ClientExt, Result,
};
use foreign_types::ForeignType;
use kernel_rust_protocol::{
    self as api,
    client::{Client, Empty},
};
use std::{
    ffi::{CString, VaList},
    mem::ManuallyDrop,
    ptr,
    sync::Arc,
};

#[repr(C)]
struct Net {
    public: ffi::kernel_net_t,
    client: Arc<Client>,
}

pub extern "C" fn create() -> *mut ffi::kernel_net_t {
    let Some(client) = crate::plugin::current_client() else {
        return ptr::null_mut();
    };
    Box::into_raw(Box::new(Net {
        public: ffi::kernel_net_t {
            get_features: Some(get_features),
            get_source_addr: Some(get_source_addr),
            get_nexthop: Some(get_nexthop),
            get_interface: Some(get_interface),
            create_address_enumerator: Some(create_address_enumerator),
            create_local_subnet_enumerator: Some(create_local_subnet_enumerator),
            add_ip: Some(add_ip),
            del_ip: Some(del_ip),
            add_route: Some(route),
            del_route: Some(route),
            destroy: Some(destroy),
        },
        client,
    }))
    .cast()
}

extern "C" fn get_features(_this: *mut ffi::kernel_net_t) -> ffi::kernel_feature_t {
    0
}

// These callbacks borrow their C arguments once at entry. RPC, response
// validation, and owned results are ordinary safe Rust after that conversion.
unsafe extern "C" fn get_source_addr(
    this: *mut ffi::kernel_net_t,
    destination: *mut ffi::host_t,
    source: *mut ffi::host_t,
) -> *mut ffi::host_t {
    let this = unsafe { &*this.cast::<Net>() };
    let operation = || -> Result<Host> {
        let parameters = unsafe {
            api::GetSourceAddress_Args {
                destination: host::endpoint(destination)?,
                source: host::optional_endpoint(source)?,
            }
        };
        let reply: api::GetSourceAddress_Reply =
            this.client.call("GetSourceAddress", &parameters)?;
        Host::parse(&reply.address)
    };
    operation().map_or(ptr::null_mut(), Host::into_ptr)
}

unsafe extern "C" fn get_nexthop(
    this: *mut ffi::kernel_net_t,
    destination: *mut ffi::host_t,
    prefix: i32,
    source: *mut ffi::host_t,
    interface: *mut *mut libc::c_char,
) -> *mut ffi::host_t {
    let this = unsafe { &*this.cast::<Net>() };
    let mut interface = unsafe { interface.as_mut() };
    if let Some(output) = interface.as_mut() {
        **output = ptr::null_mut();
    }
    let operation = || -> Result<Host> {
        let parameters = unsafe {
            api::GetNextHop_Args {
                destination: host::endpoint(destination)?,
                source: host::optional_endpoint(source)?,
                prefix: Some(prefix.into()),
            }
        };
        let reply: api::GetNextHop_Reply = this.client.call("GetNextHop", &parameters)?;
        let host = Host::parse(&reply.gateway)?;
        if let Some(output) = interface {
            *output = host::duplicate(&reply.interface)?;
        }
        Ok(host)
    };
    operation().map_or(ptr::null_mut(), Host::into_ptr)
}

unsafe extern "C" fn get_interface(
    this: *mut ffi::kernel_net_t,
    address: *mut ffi::host_t,
    name: *mut *mut libc::c_char,
) -> bool {
    let this = unsafe { &*this.cast::<Net>() };
    let mut name = unsafe { name.as_mut() };
    if let Some(output) = name.as_mut() {
        **output = ptr::null_mut();
    }
    let operation = || -> Result<()> {
        let parameters = api::GetInterface_Args {
            address: unsafe { host::endpoint(address) }?,
        };
        let reply: api::GetInterface_Reply = this.client.call("GetInterface", &parameters)?;
        if let Some(output) = name {
            *output = host::duplicate(&reply.interface)?;
        }
        Ok(())
    };
    operation().is_ok()
}

struct Item {
    host: Host,
    prefix: u8,
    name: CString,
}
#[repr(C)]
struct Snapshot {
    public: ffi::enumerator_t,
    items: Vec<Item>,
    next: usize,
    subnets: bool,
}

fn snapshot(items: Vec<Item>, subnets: bool) -> *mut ffi::enumerator_t {
    // bindgen predates stable VaList and spells the platform va_list using
    // its underlying C type. Rust's VaList has exactly that platform ABI.
    // Keep the SDK-generated table layout and cast only this callback's type.
    #[allow(clippy::missing_transmute_annotations)]
    // Infer the target ABI from the matching SDK, on every architecture.
    let venumerate = unsafe {
        std::mem::transmute::<unsafe extern "C" fn(*mut ffi::enumerator_t, VaList<'_>) -> bool, _>(
            venumerate,
        )
    };
    Box::into_raw(Box::new(Snapshot {
        public: ffi::enumerator_t {
            enumerate: Some(enumerate),
            venumerate: Some(venumerate),
            destroy: Some(destroy_snapshot),
        },
        items,
        next: 0,
        subnets,
    }))
    .cast()
}

unsafe extern "C" fn enumerate(this: *mut ffi::enumerator_t, mut args: ...) -> bool {
    // Rust owns this list and performs va_end when it leaves this scope.
    unsafe { advance(this, &mut args) }
}

unsafe extern "C" fn venumerate(this: *mut ffi::enumerator_t, args: VaList<'_>) -> bool {
    // The C caller owns this list and calls va_end itself. Suppress Rust's
    // automatic va_end for this borrowed list, including early return paths.
    let mut args = ManuallyDrop::new(args);
    unsafe { advance(this, &mut args) }
}

unsafe fn advance(this: *mut ffi::enumerator_t, args: &mut VaList<'_>) -> bool {
    // The C caller serializes iteration and supplies host_t**, and for subnets
    // uint8_t* and char**. Borrow output slots only for their individual write.
    let snapshot = unsafe { &mut *this.cast::<Snapshot>() };
    let Some(item) = snapshot.items.get(snapshot.next) else {
        return false;
    };
    snapshot.next += 1;
    if let Some(output) = unsafe { args.next_arg::<*mut *mut ffi::host_t>().as_mut() } {
        *output = item.host.as_ptr();
    }
    if snapshot.subnets {
        if let Some(output) = unsafe { args.next_arg::<*mut u8>().as_mut() } {
            *output = item.prefix;
        }
        if let Some(output) = unsafe { args.next_arg::<*mut *mut libc::c_char>().as_mut() } {
            *output = item.name.as_ptr().cast_mut();
        }
    }
    true
}

unsafe extern "C" fn destroy_snapshot(this: *mut ffi::enumerator_t) {
    unsafe {
        drop(Box::from_raw(this.cast::<Snapshot>()));
    }
}

unsafe extern "C" fn create_address_enumerator(
    this: *mut ffi::kernel_net_t,
    which: ffi::kernel_address_type_t,
) -> *mut ffi::enumerator_t {
    let this = unsafe { &*this.cast::<Net>() };
    let operation = || -> Result<Vec<Item>> {
        let reply: api::ListAddresses_Reply = this.client.call(
            "ListAddresses",
            &api::ListAddresses_Args {
                which: which.into(),
            },
        )?;
        if reply.addresses.len() > 4096 {
            return Err(status_t_FAILED);
        }
        reply
            .addresses
            .iter()
            .map(|a| {
                Ok(Item {
                    host: Host::parse(a)?,
                    prefix: 0,
                    name: CString::default(),
                })
            })
            .collect()
    };
    snapshot(operation().unwrap_or_default(), false)
}

unsafe extern "C" fn create_local_subnet_enumerator(
    this: *mut ffi::kernel_net_t,
) -> *mut ffi::enumerator_t {
    let this = unsafe { &*this.cast::<Net>() };
    let operation = || -> Result<Vec<Item>> {
        let reply: api::ListSubnets_Reply = this.client.call("ListSubnets", &Empty {})?;
        if reply.subnets.len() > 4096 {
            return Err(status_t_FAILED);
        }
        reply
            .subnets
            .iter()
            .map(|s| {
                let host = Host::parse(&s.address)?;
                let prefix = u8::try_from(s.prefix).map_err(|_| status_t_FAILED)?;
                let max = if host.family() == libc::AF_INET {
                    32
                } else {
                    128
                };
                if prefix > max {
                    return Err(status_t_FAILED);
                }
                Ok(Item {
                    host,
                    prefix,
                    name: CString::new(s.interface.as_str()).map_err(|_| status_t_FAILED)?,
                })
            })
            .collect()
    };
    snapshot(operation().unwrap_or_default(), true)
}

extern "C" fn add_ip(
    _this: *mut ffi::kernel_net_t,
    _vip: *mut ffi::host_t,
    _prefix: i32,
    _interface: *mut libc::c_char,
) -> status_t {
    status_t_NOT_SUPPORTED
}
extern "C" fn del_ip(
    _this: *mut ffi::kernel_net_t,
    _vip: *mut ffi::host_t,
    _prefix: i32,
    _wait: bool,
) -> status_t {
    status_t_NOT_SUPPORTED
}
extern "C" fn route(
    _this: *mut ffi::kernel_net_t,
    _dst: ffi::chunk_t,
    _prefix: u8,
    _gateway: *mut ffi::host_t,
    _source: *mut ffi::host_t,
    _interface: *mut libc::c_char,
    _pass: bool,
) -> status_t {
    status_t_NOT_SUPPORTED
}

unsafe extern "C" fn destroy(this: *mut ffi::kernel_net_t) {
    unsafe {
        drop(Box::from_raw(this.cast::<Net>()));
    }
}
