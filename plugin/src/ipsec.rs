// SPDX-License-Identifier: GPL-2.0-or-later
use crate::{ffi, host, status_t, status_t_FAILED, status_t_SUCCESS, ClientExt, Result};
use kernel_rust_protocol::{self as api, client::Client, context};
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
    let (src, dst) = unsafe { (host::endpoint(id.src)?, host::endpoint(id.dst)?) };
    Ok(api::SaId {
        src,
        dst,
        spi: u32::from_be(id.spi),
        protocol: id.proto,
        mark: host::mark(id.mark),
        interface_id: id.if_id,
    })
}

unsafe extern "C" fn get_features(this: *mut ffi::kernel_ipsec_t) -> ffi::kernel_feature_t {
    let this = unsafe { &*this.cast::<Ipsec>() };
    this.client.features() as _
}

unsafe extern "C" fn get_spi(
    this: *mut ffi::kernel_ipsec_t,
    src: *mut ffi::host_t,
    dst: *mut ffi::host_t,
    protocol: u8,
    spi: *mut u32,
) -> status_t {
    let this = unsafe { &*this.cast::<Ipsec>() };
    let operation = || -> Result<()> {
        let (src, dst, min, max) = unsafe {
            (
                host::endpoint(src)?,
                host::endpoint(dst)?,
                host::setting_int(c"%s.spi_min", 0xc0000000u32 as i32) as u32,
                host::setting_int(c"%s.spi_max", 0xcfffffff_u32 as i32) as u32,
            )
        };
        let value = this.client.call(this.client.rpc().allocate_spi(
            context::current(),
            src,
            dst,
            protocol,
            min,
            max,
        ))?;
        let spi = unsafe { spi.as_mut() }.ok_or(status_t_FAILED)?;
        if value < 256 {
            return Err(status_t_FAILED);
        }
        *spi = value.to_be();
        Ok(())
    };
    status(operation())
}

unsafe extern "C" fn get_cpi(
    this: *mut ffi::kernel_ipsec_t,
    src: *mut ffi::host_t,
    dst: *mut ffi::host_t,
    cpi: *mut u16,
) -> status_t {
    let this = unsafe { &*this.cast::<Ipsec>() };
    status((|| -> Result<()> {
        let src = unsafe { host::endpoint(src) }?;
        let dst = unsafe { host::endpoint(dst) }?;
        let value =
            this.client
                .call(this.client.rpc().allocate_cpi(context::current(), src, dst))?;
        let cpi = unsafe { cpi.as_mut() }.ok_or(status_t_FAILED)?;
        *cpi = value.to_be();
        Ok(())
    })())
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
            reqid: d.reqid,
            acquire_sequence: d.seq,
            mode: d.mode,
            src_selectors: unsafe { host::selectors(d.src_ts) }?,
            dst_selectors: unsafe { host::selectors(d.dst_ts) }?,
            interface: unsafe { host::optional_string(d.interface) }?,
            ipcomp: d.ipcomp,
            cpi: u16::from_be(d.cpi),
            cpu: d.cpu,
            hw_offload: d.hw_offload,
            security_label: unsafe { host::label(d.label) }?,
            encryption,
            integrity,
            lifetime: unsafe { d.lifetime.as_ref() }.map(|lifetime| api::Lifetime {
                time: api::LifetimeLimit {
                    life: lifetime.time.life,
                    rekey: lifetime.time.rekey,
                    jitter: lifetime.time.jitter,
                },
                bytes: api::LifetimeLimit {
                    life: lifetime.bytes.life,
                    rekey: lifetime.bytes.rekey,
                    jitter: lifetime.bytes.jitter,
                },
                packets: api::LifetimeLimit {
                    life: lifetime.packets.life,
                    rekey: lifetime.packets.rekey,
                    jitter: lifetime.packets.jitter,
                },
            }),
            replay_window: d.replay_window,
            esn: d.esn,
            udp_encapsulation: d.encap,
            output_mark: host::mark(d.mark),
            tfc: d.tfc,
            copy_df: d.copy_df,
            copy_ecn: d.copy_ecn,
            copy_dscp: d.copy_dscp,
            iptfs_dont_fragment: d.iptfs_dont_frag,
            forward_icmp: d.forward_icmp,
            initiator: d.initiator,
            inbound: d.inbound,
            update: d.update,
        };
        this.client
            .call(this.client.rpc().install_sa(context::current(), id, config))?;
        Ok(())
    };
    status(operation())
}

unsafe extern "C" fn update_sa(
    this: *mut ffi::kernel_ipsec_t,
    id: *mut ffi::kernel_ipsec_sa_id_t,
    data: *mut ffi::kernel_ipsec_update_sa_t,
) -> status_t {
    let this = unsafe { &*this.cast::<Ipsec>() };
    status((|| -> Result<()> {
        let d = unsafe { &*data };
        let id = unsafe { sa_id(&*id) }?;
        let config = api::SaUpdate {
            mode: d.mode,
            cpi: u16::from_be(d.cpi),
            src: unsafe { host::endpoint(d.new_src) }?,
            dst: unsafe { host::endpoint(d.new_dst) }?,
            udp_encapsulation: d.encap,
            new_udp_encapsulation: d.new_encap,
            old_reqid: d.old_reqid,
            new_reqid: d.new_reqid,
            hw_offload: d.hw_offload,
            src_selectors: unsafe { host::selectors(d.src_ts) }?,
            dst_selectors: unsafe { host::selectors(d.dst_ts) }?,
            interface: unsafe { host::optional_string(d.interface) }?,
            inbound: d.inbound,
        };
        this.client
            .call(this.client.rpc().update_sa(context::current(), id, config))?;
        Ok(())
    })())
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
        let id = unsafe { sa_id(&*id) }?;
        let cpi = u16::from_be(unsafe { (*data).cpi });
        let reply = this
            .client
            .call(this.client.rpc().query_sa(context::current(), id, cpi))?;
        let last = last_use(reply.last_use)?;
        if let Some(output) = unsafe { bytes.as_mut() } {
            *output = reply.bytes;
        }
        if let Some(output) = unsafe { packets.as_mut() } {
            *output = reply.packets;
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
        let id = unsafe { sa_id(&*id) }?;
        let cpi = u16::from_be(unsafe { (*data).cpi });
        this.client
            .call(this.client.rpc().remove_sa(context::current(), id, cpi))?;
        Ok(())
    };
    status(operation())
}

unsafe extern "C" fn flush_sas(this: *mut ffi::kernel_ipsec_t) -> status_t {
    let this = unsafe { &*this.cast::<Ipsec>() };
    this.client
        .empty(this.client.rpc().flush_sas(context::current()))
}

unsafe fn policy_id(id: &ffi::kernel_ipsec_policy_id_t) -> Result<api::PolicyId> {
    let (src, dst) = unsafe { (host::selector(id.src_ts)?, host::selector(id.dst_ts)?) };
    Ok(api::PolicyId {
        direction: id.dir,
        src,
        dst,
        mark: host::mark(id.mark),
        interface_id: id.if_id,
        interface: unsafe { host::optional_string(id.interface) }?,
        security_label: unsafe { host::label(id.label) }?,
    })
}

unsafe fn policy_config(d: &ffi::kernel_ipsec_manage_policy_t) -> Result<api::PolicyConfig> {
    let (src, dst) = unsafe {
        (
            host::optional_endpoint(d.src)?,
            host::optional_endpoint(d.dst)?,
        )
    };
    Ok(api::PolicyConfig {
        kind: d.type_,
        priority: d.prio,
        manual_priority: d.manual_prio,
        hw_offload: d.hw_offload,
        pcpu_acquires: d.pcpu_acquires,
        forward_icmp: d.forward_icmp,
        src,
        dst,
        sa: unsafe { d.sa.as_ref() }.map(|sa| api::PolicySa {
            mode: sa.mode,
            reqid: sa.reqid,
            policy_count: sa.policy_count,
            esp: api::ProtocolSa {
                used: sa.esp.use_,
                spi: u32::from_be(sa.esp.spi),
            },
            ah: api::ProtocolSa {
                used: sa.ah.use_,
                spi: u32::from_be(sa.ah.spi),
            },
            ipcomp: api::CompressionSa {
                transform: sa.ipcomp.transform,
                cpi: u16::from_be(sa.ipcomp.cpi),
            },
        }),
    })
}

unsafe extern "C" fn add_policy(
    this: *mut ffi::kernel_ipsec_t,
    id: *mut ffi::kernel_ipsec_policy_id_t,
    data: *mut ffi::kernel_ipsec_manage_policy_t,
) -> status_t {
    let this = unsafe { &*this.cast::<Ipsec>() };
    let operation = || -> Result<()> {
        let id = unsafe { policy_id(&*id) }?;
        let config = unsafe { policy_config(&*data) }?;
        this.client.call(
            this.client
                .rpc()
                .install_policy(context::current(), id, config),
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
        let id = unsafe { policy_id(&*id) }?;
        let config = unsafe { policy_config(&*data) }?;
        this.client.call(
            this.client
                .rpc()
                .remove_policy(context::current(), id, config),
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
        let id = unsafe { policy_id(&*id) }?;
        let last = last_use(
            this.client
                .call(this.client.rpc().query_policy(context::current(), id))?,
        )?;
        if let Some(output) = unsafe { time.as_mut() } {
            *output = last;
        }
        Ok(())
    };
    status(operation())
}

unsafe extern "C" fn flush_policies(this: *mut ffi::kernel_ipsec_t) -> status_t {
    let this = unsafe { &*this.cast::<Ipsec>() };
    this.client
        .empty(this.client.rpc().flush_policies(context::current()))
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
            this.client
                .rpc()
                .bypass_port(context::current(), family as u16, port),
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
fn last_use(value: u64) -> Result<ffi::time_t> {
    ffi::time_t::try_from(value).map_err(|_| status_t_FAILED)
}
