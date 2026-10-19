// SPDX-License-Identifier: GPL-2.0-or-later
use crate::{
    ffi, host, status_t, status_t_FAILED, status_t_NOT_SUPPORTED, status_t_SUCCESS, ClientExt,
    Result,
};
use kernel_rust_protocol::{
    self as api,
    client::{Client, Empty},
};
use std::{mem, os::fd::BorrowedFd, ptr, sync::Arc};

#[repr(C)]
struct Ipsec {
    public: ffi::kernel_ipsec_t,
    client: Arc<Client>,
}

pub extern "C" fn create() -> *mut ffi::kernel_ipsec_t {
    let Some(client) = crate::plugin::current_client() else {
        return ptr::null_mut();
    };
    Box::into_raw(Box::new(Ipsec {
        public: ffi::kernel_ipsec_t {
            get_features: Some(get_features),
            get_spi: Some(get_spi),
            get_cpi: Some(get_cpi),
            add_sa: Some(add_sa),
            update_sa: Some(update_sa),
            query_sa: Some(query_sa),
            del_sa: Some(del_sa),
            flush_sas: Some(flush_sas),
            add_policy: Some(add_policy),
            query_policy: Some(query_policy),
            del_policy: Some(del_policy),
            flush_policies: Some(flush_policies),
            bypass_socket: Some(bypass_socket),
            enable_udp_decap: Some(enable_udp_decap),
            destroy: Some(destroy),
        },
        client,
    }))
    .cast()
}

// C callbacks borrow live objects and output slots at entry. RPC and value
// validation run outside unsafe; no raw pointer is retained by the RPC client.
unsafe fn sa_id(id: &ffi::kernel_ipsec_sa_id_t) -> Result<api::SaId> {
    if id.proto != libc::IPPROTO_ESP as u8 || id.if_id == 0 {
        return Err(status_t_NOT_SUPPORTED);
    }
    let (src, dst) = unsafe { (host::endpoint(id.src)?, host::endpoint(id.dst)?) };
    Ok(api::SaId {
        src,
        dst,
        spi: u32::from_be(id.spi).into(),
        mark: host::mark(id.mark),
        interfaceId: id.if_id.into(),
    })
}

unsafe extern "C" fn get_features(this: *mut ffi::kernel_ipsec_t) -> ffi::kernel_feature_t {
    let this = unsafe { &*this.cast::<Ipsec>() };
    this.client.features()
}

unsafe extern "C" fn get_spi(
    this: *mut ffi::kernel_ipsec_t,
    src: *mut ffi::host_t,
    dst: *mut ffi::host_t,
    protocol: u8,
    spi: *mut u32,
) -> status_t {
    if protocol != libc::IPPROTO_ESP as u8 {
        return status_t_NOT_SUPPORTED;
    }
    let this = unsafe { &*this.cast::<Ipsec>() };
    let operation = || -> Result<()> {
        let parameters = unsafe {
            api::AllocateSpi_Args {
                src: host::endpoint(src)?,
                dst: host::endpoint(dst)?,
                minimum: (host::setting_int(c"%s.spi_min", 0xc0000000u32 as i32) as u32).into(),
                maximum: (host::setting_int(c"%s.spi_max", 0xcfffffff_u32 as i32) as u32).into(),
            }
        };
        let reply: api::AllocateSpi_Reply = this.client.call("AllocateSpi", &parameters)?;
        let spi = unsafe { spi.as_mut() }.ok_or(status_t_FAILED)?;
        let value = u32::try_from(reply.spi).map_err(|_| status_t_FAILED)?;
        if value < 256 {
            return Err(status_t_FAILED);
        }
        *spi = value.to_be();
        Ok(())
    };
    status(operation())
}

extern "C" fn get_cpi(
    _this: *mut ffi::kernel_ipsec_t,
    _src: *mut ffi::host_t,
    _dst: *mut ffi::host_t,
    _cpi: *mut u16,
) -> status_t {
    status_t_NOT_SUPPORTED
}

unsafe extern "C" fn add_sa(
    this: *mut ffi::kernel_ipsec_t,
    id: *mut ffi::kernel_ipsec_sa_id_t,
    data: *mut ffi::kernel_ipsec_add_sa_t,
) -> status_t {
    let this = unsafe { &*this.cast::<Ipsec>() };
    let operation = || -> Result<()> {
        let d = unsafe { &*data };
        let id = unsafe { sa_id(&*id) }?;
        if d.mode != ffi::ipsec_mode_t_MODE_TUNNEL
            || d.ipcomp != 0
            || d.cpi != 0
            || !d.label.is_null()
            || d.hw_offload != ffi::hw_offload_t_HW_OFFLOAD_NO
            || d.cpu != ffi::CPU_ID_MAX
            || d.forward_icmp
            || d.enc_key.len > 8192
            || d.int_key.len > 8192
            || !unsafe { host::unrestricted_interface(d.interface) }
        {
            return Err(status_t_NOT_SUPPORTED);
        }
        let lifetime = unsafe { d.lifetime.as_ref() }.ok_or(status_t_FAILED)?;
        let encryption = unsafe {
            host::algorithm(
                d.enc_alg,
                d.enc_key,
                ffi::transform_type_t_ENCRYPTION_ALGORITHM,
            )
        }?;
        let integrity = unsafe {
            host::algorithm(
                d.int_alg,
                d.int_key,
                ffi::transform_type_t_INTEGRITY_ALGORITHM,
            )
        }?;
        let config = api::SaConfig {
            reqid: d.reqid.into(),
            acquireSequence: d.seq.into(),
            encryption,
            integrity,
            lifetime: api::Lifetime {
                timeLife: i64::try_from(lifetime.time.life).map_err(|_| status_t_NOT_SUPPORTED)?,
                timeRekey: i64::try_from(lifetime.time.rekey)
                    .map_err(|_| status_t_NOT_SUPPORTED)?,
                byteLife: lifetime.bytes.life.to_string(),
                byteRekey: lifetime.bytes.rekey.to_string(),
                packetLife: lifetime.packets.life.to_string(),
                packetRekey: lifetime.packets.rekey.to_string(),
            },
            replayWindow: d.replay_window.into(),
            esn: d.esn,
            udpEncapsulation: d.encap,
            outputMark: host::mark(d.mark),
            tfc: d.tfc.into(),
            copyDf: d.copy_df,
            copyEcn: d.copy_ecn,
            copyDscp: d.copy_dscp.into(),
            inbound: d.inbound,
            update: d.update,
        };
        this.client
            .call::<_, Empty>("InstallSa", &api::InstallSa_Args { id, config })?;
        Ok(())
    };
    status(operation())
}

extern "C" fn update_sa(
    _this: *mut ffi::kernel_ipsec_t,
    _id: *mut ffi::kernel_ipsec_sa_id_t,
    _data: *mut ffi::kernel_ipsec_update_sa_t,
) -> status_t {
    status_t_NOT_SUPPORTED
}

unsafe extern "C" fn query_sa(
    this: *mut ffi::kernel_ipsec_t,
    id: *mut ffi::kernel_ipsec_sa_id_t,
    data: *mut ffi::kernel_ipsec_query_sa_t,
    bytes: *mut u64,
    packets: *mut u64,
    time: *mut ffi::time_t,
) -> status_t {
    let this = unsafe { &*this.cast::<Ipsec>() };
    let operation = || -> Result<()> {
        if unsafe { (*data).cpi } != 0 {
            return Err(status_t_NOT_SUPPORTED);
        }
        let reply: api::QuerySa_Reply = this.client.call(
            "QuerySa",
            &api::QuerySa_Args {
                id: unsafe { sa_id(&*id) }?,
            },
        )?;
        let b = decimal(&reply.bytes)?;
        let p = decimal(&reply.packets)?;
        let last = last_use(reply.lastUse)?;
        if let Some(output) = unsafe { bytes.as_mut() } {
            *output = b;
        }
        if let Some(output) = unsafe { packets.as_mut() } {
            *output = p;
        }
        if let Some(output) = unsafe { time.as_mut() } {
            *output = last;
        }
        Ok(())
    };
    status(operation())
}

unsafe extern "C" fn del_sa(
    this: *mut ffi::kernel_ipsec_t,
    id: *mut ffi::kernel_ipsec_sa_id_t,
    data: *mut ffi::kernel_ipsec_del_sa_t,
) -> status_t {
    let this = unsafe { &*this.cast::<Ipsec>() };
    let operation = || -> Result<()> {
        if unsafe { (*data).cpi } != 0 {
            return Err(status_t_NOT_SUPPORTED);
        }
        this.client.call::<_, Empty>(
            "RemoveSa",
            &api::RemoveSa_Args {
                id: unsafe { sa_id(&*id) }?,
            },
        )?;
        Ok(())
    };
    status(operation())
}

unsafe extern "C" fn flush_sas(this: *mut ffi::kernel_ipsec_t) -> status_t {
    let this = unsafe { &*this.cast::<Ipsec>() };
    this.client.empty("FlushSas", &Empty {})
}

unsafe fn policy_id(id: &ffi::kernel_ipsec_policy_id_t) -> Result<api::PolicyId> {
    if id.if_id == 0
        || !id.label.is_null()
        || !unsafe { host::unrestricted_interface(id.interface) }
    {
        return Err(status_t_NOT_SUPPORTED);
    }
    let (src, dst) = unsafe { (host::selector(id.src_ts)?, host::selector(id.dst_ts)?) };
    Ok(api::PolicyId {
        direction: id.dir.into(),
        src,
        dst,
        mark: host::mark(id.mark),
        interfaceId: id.if_id.into(),
    })
}

unsafe fn policy_config(d: &ffi::kernel_ipsec_manage_policy_t) -> Result<api::PolicyConfig> {
    let sa = unsafe { d.sa.as_ref() }.ok_or(status_t_NOT_SUPPORTED)?;
    if sa.mode != ffi::ipsec_mode_t_MODE_TUNNEL
        || sa.ah.use_
        || sa.ipcomp.transform != 0
        || d.hw_offload != ffi::hw_offload_t_HW_OFFLOAD_NO
        || d.pcpu_acquires
        || d.forward_icmp
    {
        return Err(status_t_NOT_SUPPORTED);
    }
    let (src, dst) = unsafe { (host::endpoint(d.src)?, host::endpoint(d.dst)?) };
    Ok(api::PolicyConfig {
        kind: d.type_.into(),
        priority: d.prio.into(),
        manualPriority: d.manual_prio.into(),
        src,
        dst,
        reqid: sa.reqid.into(),
        policyCount: sa.policy_count.into(),
        espSpi: sa.esp.use_.then_some(u32::from_be(sa.esp.spi).into()),
    })
}

unsafe extern "C" fn add_policy(
    this: *mut ffi::kernel_ipsec_t,
    id: *mut ffi::kernel_ipsec_policy_id_t,
    data: *mut ffi::kernel_ipsec_manage_policy_t,
) -> status_t {
    let this = unsafe { &*this.cast::<Ipsec>() };
    let operation = || -> Result<()> {
        this.client.call::<_, Empty>(
            "InstallPolicy",
            &api::InstallPolicy_Args {
                id: unsafe { policy_id(&*id) }?,
                config: unsafe { policy_config(&*data) }?,
            },
        )?;
        Ok(())
    };
    status(operation())
}

unsafe extern "C" fn del_policy(
    this: *mut ffi::kernel_ipsec_t,
    id: *mut ffi::kernel_ipsec_policy_id_t,
    data: *mut ffi::kernel_ipsec_manage_policy_t,
) -> status_t {
    let this = unsafe { &*this.cast::<Ipsec>() };
    let operation = || -> Result<()> {
        this.client.call::<_, Empty>(
            "RemovePolicy",
            &api::RemovePolicy_Args {
                id: unsafe { policy_id(&*id) }?,
                config: unsafe { policy_config(&*data) }?,
            },
        )?;
        Ok(())
    };
    status(operation())
}

unsafe extern "C" fn query_policy(
    this: *mut ffi::kernel_ipsec_t,
    id: *mut ffi::kernel_ipsec_policy_id_t,
    _data: *mut ffi::kernel_ipsec_query_policy_t,
    time: *mut ffi::time_t,
) -> status_t {
    let this = unsafe { &*this.cast::<Ipsec>() };
    let operation = || -> Result<()> {
        let reply: api::QueryPolicy_Reply = this.client.call(
            "QueryPolicy",
            &api::QueryPolicy_Args {
                id: unsafe { policy_id(&*id) }?,
            },
        )?;
        let last = last_use(reply.lastUse)?;
        if let Some(output) = unsafe { time.as_mut() } {
            *output = last;
        }
        Ok(())
    };
    status(operation())
}

unsafe extern "C" fn flush_policies(this: *mut ffi::kernel_ipsec_t) -> status_t {
    let this = unsafe { &*this.cast::<Ipsec>() };
    this.client.empty("FlushPolicies", &Empty {})
}

unsafe extern "C" fn bypass_socket(this: *mut ffi::kernel_ipsec_t, fd: i32, family: i32) -> bool {
    let this = unsafe { &*this.cast::<Ipsec>() };
    if fd < 0 {
        return false;
    }
    // SAFETY: the C socket plugin lends this open fd for the callback only.
    let socket = unsafe { BorrowedFd::borrow_raw(fd) };
    let Ok(address) = rustix::net::getsockname(socket) else {
        return false;
    };
    let port = match family {
        libc::AF_INET => rustix::net::SocketAddrV4::try_from(address).map(|a| a.port()),
        libc::AF_INET6 => rustix::net::SocketAddrV6::try_from(address).map(|a| a.port()),
        _ => return false,
    };
    let Ok(port) = port else { return false };
    port >= 1024
        && this.client.empty(
            "BypassPort",
            &api::BypassPort_Args {
                family: family.into(),
                port: port.into(),
            },
        ) == status_t_SUCCESS
}

unsafe extern "C" fn enable_udp_decap(
    _this: *mut ffi::kernel_ipsec_t,
    fd: i32,
    _family: i32,
    _port: u16,
) -> bool {
    // High-port sockets belong to charon; these options need no capabilities.
    let encap: libc::c_int = 2; // UDP_ENCAP_ESPINUDP, linux/udp.h
    let gro: libc::c_int = 1;
    unsafe {
        if libc::setsockopt(
            fd,
            libc::IPPROTO_UDP,
            libc::UDP_ENCAP,
            ptr::from_ref(&encap).cast(),
            mem::size_of_val(&encap) as _,
        ) < 0
        {
            return false;
        }
        libc::setsockopt(
            fd,
            libc::IPPROTO_UDP,
            libc::UDP_GRO,
            ptr::from_ref(&gro).cast(),
            mem::size_of_val(&gro) as _,
        );
    }
    true
}

unsafe extern "C" fn destroy(this: *mut ffi::kernel_ipsec_t) {
    unsafe {
        drop(Box::from_raw(this.cast::<Ipsec>()));
    }
}

fn status(result: Result<()>) -> status_t {
    result.map_or_else(|status| status, |_| status_t_SUCCESS)
}
fn decimal(value: &str) -> Result<u64> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(status_t_FAILED);
    }
    value.parse().map_err(|_| status_t_FAILED)
}
fn last_use(value: i64) -> Result<ffi::time_t> {
    if value < 0 {
        return Err(status_t_FAILED);
    }
    ffi::time_t::try_from(value).map_err(|_| status_t_FAILED)
}
