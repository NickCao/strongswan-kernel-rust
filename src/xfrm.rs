// SPDX-License-Identifier: GPL-2.0-or-later
// Policy and SA semantics ported from kernel_netlink_ipsec.c (Martin Willi,
// Tobias Brunner and contributors; Copyright secunet Security Networks AG).
// Packet layouts and serialization are supplied by netlink-packet-xfrm.
use crate::{
    backend::{endpoint, rpc_selector},
    error::invalid,
    model::*,
    netlink::{Message, Netlink, NlFamily, NlmF, Reply},
    policy::{Policies, PolicyKernel, PolicyStatus},
    rpc_api as rpc,
};
use ipnet::IpNet;
use netlink_packet_core::{DefaultNla, Emitable, Nla, NlasIterator, Parseable};
use netlink_packet_xfrm::{self as packet, XfrmAttrs as Attr, XfrmMessage};
use std::{
    collections::{HashMap, HashSet},
    io,
    net::IpAddr,
};

// Linux 6.10 added this attribute; use the packet crate's extension mechanism
// until it has a dedicated variant. Values are XFRM_SA_DIR_IN/OUT.
const SA_DIR: u16 = 33;
pub const NEWSA: u16 = packet::XFRM_MSG_NEWSA;

// kernel_feature_t from strongSwan's kernel_interface.h.
const KERNEL_ESP_V3_TFC: u32 = 1 << 0;
const KERNEL_REQUIRE_UDP_ENCAPSULATION: u32 = 1 << 2;
const KERNEL_POLICY_SPI: u32 = 1 << 4;
const KERNEL_SA_USE_TIME: u32 = 1 << 5;
const KERNEL_ACQUIRE_SEQ: u32 = 1 << 6;

fn missing() -> io::Error {
    io::Error::from_raw_os_error(libc::ENOENT)
}
fn unsupported() -> io::Error {
    io::Error::from_raw_os_error(libc::EOPNOTSUPP)
}
fn monotonic_use_time(time: u64) -> io::Result<u64> {
    if time == 0 {
        return Ok(0);
    }
    // XFRM reports Unix seconds; strongSwan expects CLOCK_MONOTONIC seconds.
    let monotonic = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| invalid())?
        .as_secs();
    Ok((monotonic.tv_sec as u64).saturating_sub(wall.saturating_sub(time)))
}
fn message(flags: NlmF, value: &XfrmMessage) -> Message {
    Message::new(value.message_type(), flags, value)
}
fn host(family: u16, address: packet::Address, port: u16) -> io::Result<Host> {
    let ip = match family as i32 {
        libc::AF_INET => address.to_ipv4().into(),
        libc::AF_INET6 => address.to_ipv6().into(),
        _ => return Err(invalid()),
    };
    Ok(Host { ip, port })
}
fn id_attrs(mark: Mark, if_id: u32) -> Vec<Attr> {
    let mut attrs = Vec::new();
    if mark.mask != 0 {
        attrs.push(Attr::Mark(packet::Mark {
            value: mark.value,
            mask: mark.mask,
        }));
    }
    if if_id != 0 {
        attrs.push(Attr::IfId(if_id));
    }
    attrs
}
fn direction(inbound: bool) -> Attr {
    Attr::Other(DefaultNla::new(SA_DIR, vec![if inbound { 1 } else { 2 }]))
}
fn sa_id(id: &SaId) -> packet::UserSaId {
    packet::UserSaId {
        daddr: packet::Address::from_ip(&id.dst.ip),
        spi: id.spi,
        family: id.dst.family(),
        proto: id.proto,
    }
}
fn sa_reply(reply: &Reply) -> io::Result<packet::state::ModifyMessage> {
    packet::state::ModifyMessage::parse(reply.payload.as_slice()).map_err(io::Error::other)
}
pub fn selector(src: &Ts, dst: &Ts, interface: &str) -> io::Result<packet::Selector> {
    if src.from.family() != dst.from.family() {
        return Err(invalid());
    }
    let (src_net, prefixlen_s) = src.subnet();
    let (dst_net, prefixlen_d) = dst.subnet();
    let proto = src.proto.max(dst.proto);
    let (mut sport, mut sport_mask) = src.ports();
    let (mut dport, mut dport_mask) = dst.ports();
    if [1, 58].contains(&proto) && (sport != 0 || dport != 0) {
        let port = sport.max(dport);
        sport = port >> 8;
        dport = port & 0xff;
        sport_mask = if sport == 0 { 0 } else { u16::MAX };
        dport_mask = if dport == 0 { 0 } else { u16::MAX };
    }
    Ok(packet::Selector {
        saddr: packet::Address::from_ip(&src_net.ip),
        daddr: packet::Address::from_ip(&dst_net.ip),
        family: src.from.family(),
        prefixlen_s,
        prefixlen_d,
        proto,
        sport,
        sport_mask,
        dport,
        dport_mask,
        ifindex: crate::network::index(interface)? as i32,
        user: 0,
    })
}
fn selector_ts(selector: &packet::Selector, source: bool) -> io::Result<Ts> {
    let (address, prefix, port, mask) = if source {
        (
            &selector.saddr,
            selector.prefixlen_s,
            selector.sport,
            selector.sport_mask,
        )
    } else {
        (
            &selector.daddr,
            selector.prefixlen_d,
            selector.dport,
            selector.dport_mask,
        )
    };
    let (port, mask) = if [1, 58].contains(&selector.proto) {
        (
            (selector.sport << 8) | selector.dport,
            if selector.sport_mask | selector.dport_mask != 0 {
                u16::MAX
            } else {
                0
            },
        )
    } else {
        (port, mask)
    };
    Ts::from_subnet(
        host(selector.family, *address, 0)?,
        prefix,
        selector.proto,
        port & mask,
        (port & mask) | !mask,
    )
}
fn algorithm(name: &str) -> io::Result<[u8; packet::XFRM_ALG_NAME_LEN]> {
    if name.is_empty() || name.len() >= packet::XFRM_ALG_NAME_LEN || !name.is_ascii() {
        return Err(unsupported());
    }
    let mut bytes = [0; packet::XFRM_ALG_NAME_LEN];
    bytes[..name.len()].copy_from_slice(name.as_bytes());
    Ok(bytes)
}
fn enc_algorithm(id: u16) -> Option<(&'static str, Option<u32>)> {
    Some(match id {
        2 => ("des", None),
        3 => ("des3_ede", None),
        6 => ("cast5", None),
        7 => ("blowfish", None),
        11 => ("cipher_null", None),
        12 => ("aes", None),
        13 => ("rfc3686(ctr(aes))", None),
        14..=16 => ("rfc4309(ccm(aes))", Some(64 + (id as u32 - 14) * 32)),
        18..=20 => ("rfc4106(gcm(aes))", Some(64 + (id as u32 - 18) * 32)),
        21 => ("rfc4543(gcm(aes))", Some(128)),
        23 => ("cbc(camellia)", None),
        28 => ("rfc7539esp(chacha20,poly1305)", Some(128)),
        1026 => ("serpent", None),
        1027 => ("twofish", None),
        _ => return None,
    })
}
fn int_algorithm(id: u16) -> Option<(&'static str, Option<u32>)> {
    Some(match id {
        1 => ("md5", None),
        2 => ("sha1", None),
        5 => ("xcbc(aes)", None),
        6 => ("hmac(md5)", Some(128)),
        7 => ("hmac(sha1)", Some(160)),
        8 => ("cmac(aes)", None),
        12 => ("hmac(sha256)", Some(128)),
        13 => ("hmac(sha384)", None),
        14 => ("hmac(sha512)", None),
        1026 => ("sha256", None),
        1027 => ("hmac(sha256)", Some(256)),
        1028 => ("hmac(sha384)", Some(384)),
        1029 => ("hmac(sha512)", Some(512)),
        _ => return None,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PolicyKey {
    src: IpNet,
    dst: IpNet,
    src_port: u16,
    src_port_mask: u16,
    dst_port: u16,
    dst_port_mask: u16,
    protocol: u8,
    dir: u8,
    mark: Mark,
    if_id: u32,
}
pub struct Xfrm {
    socket: Netlink,
    pub sas: HashSet<crate::model::SaId>,
    allocations: HashSet<(IpAddr, IpAddr, u32, u8)>,
    pub sa_dir: bool,
    pub lastused: bool,
}
impl Xfrm {
    pub fn new() -> io::Result<Self> {
        // The service's ProcSubset=pid sandbox hides global /proc files.
        let uname = rustix::system::uname();
        let release = uname.release().to_str().map_err(io::Error::other)?;
        let mut parts = release
            .trim()
            .split('.')
            .map(|s| s.parse::<u32>().unwrap_or(0));
        let version = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
        Ok(Self {
            socket: Netlink::new(NlFamily::Xfrm)?,
            sas: HashSet::new(),
            allocations: HashSet::new(),
            sa_dir: version >= (6, 10),
            lastused: version >= (6, 2),
        })
    }
    pub fn features(&self) -> u32 {
        KERNEL_ESP_V3_TFC
            | KERNEL_REQUIRE_UDP_ENCAPSULATION
            | KERNEL_POLICY_SPI
            | KERNEL_ACQUIRE_SEQ
            | if self.lastused { KERNEL_SA_USE_TIME } else { 0 }
    }
    pub fn allocate(
        &mut self,
        src: Host,
        dst: Host,
        proto: u8,
        min: u32,
        max: u32,
    ) -> io::Result<u32> {
        if src.family() != dst.family() || proto != 50 || min == 0 || min > max {
            return Err(invalid());
        }
        let request = XfrmMessage::AllocSpi(packet::state::AllocSpiMessage {
            spi_info: packet::UserSpiInfo {
                info: packet::UserSaInfo {
                    saddr: packet::Address::from_ip(&src.ip),
                    id: packet::Id {
                        daddr: packet::Address::from_ip(&dst.ip),
                        proto,
                        ..Default::default()
                    },
                    family: src.family(),
                    mode: packet::XFRM_MODE_TUNNEL,
                    ..Default::default()
                },
                min,
                max,
            },
            nlas: if self.sa_dir {
                vec![direction(true)]
            } else {
                Vec::new()
            },
        });
        for reply in self.socket.request(&message(NlmF::empty(), &request))? {
            if reply.kind == NEWSA {
                let sa = sa_reply(&reply)?;
                let spi = sa.user_sa_info.id.spi;
                if spi == 0 {
                    return Err(invalid());
                }
                self.allocations.insert((src.ip, dst.ip, spi, proto));
                return Ok(spi);
            }
        }
        Err(invalid())
    }
    fn owned(&self, id: &crate::model::SaId) -> bool {
        self.sas.contains(&id.key())
            || self
                .allocations
                .contains(&(id.src.ip, id.dst.ip, id.spi, id.proto))
    }
    fn sa_message(&self, id: &SaId, data: &AddSa<'_>) -> io::Result<XfrmMessage> {
        let mut flags = packet::XFRM_STATE_AF_UNSPEC;
        if !data.copy_ecn {
            flags |= packet::XFRM_STATE_NOECN;
        }
        if data.inbound && [1, 2].contains(&data.copy_dscp) {
            flags |= packet::XFRM_STATE_DECAP_DSCP;
        }
        if !data.inbound && !data.copy_df {
            flags |= packet::XFRM_STATE_NOPMTUDISC;
        }
        if data.esn {
            flags |= packet::XFRM_STATE_ESN;
        }
        let replay = if data.inbound {
            data.replay_window
        } else {
            u32::from(data.esn && !self.sa_dir)
        };
        let info = packet::UserSaInfo {
            saddr: packet::Address::from_ip(&id.src.ip),
            id: packet::Id {
                daddr: packet::Address::from_ip(&id.dst.ip),
                spi: id.spi,
                proto: id.proto,
            },
            family: id.src.family(),
            mode: packet::XFRM_MODE_TUNNEL,
            reqid: data.reqid,
            seq: data.seq,
            flags,
            replay_window: if !data.esn && replay <= 32 {
                replay as u8
            } else {
                0
            },
            lifetime_cfg: packet::LifetimeConfig {
                soft_byte_limit: nonzero(data.lifetime[3]),
                hard_byte_limit: nonzero(data.lifetime[2]),
                soft_packet_limit: nonzero(data.lifetime[5]),
                hard_packet_limit: nonzero(data.lifetime[4]),
                soft_add_expires_seconds: data.lifetime[1],
                hard_add_expires_seconds: data.lifetime[0],
                ..Default::default()
            },
            ..Default::default()
        };
        let mut nlas = Vec::new();
        if data.enc_alg != 1024 {
            let (name, icv) = enc_algorithm(data.enc_alg)
                .or_else(|| (!data.enc_name.is_empty()).then_some((data.enc_name.as_str(), None)))
                .ok_or_else(unsupported)?;
            let alg_name = algorithm(name)?;
            let alg_key = data.enc_key.to_vec();
            let alg_key_len = alg_key.len() as u32 * 8;
            nlas.push(match icv {
                Some(alg_icv_len) => Attr::EncryptionAlgAead(packet::AlgAead {
                    alg_name,
                    alg_key,
                    alg_key_len,
                    alg_icv_len,
                }),
                None => Attr::EncryptionAlg(packet::Alg {
                    alg_name,
                    alg_key,
                    alg_key_len,
                }),
            });
        }
        if data.int_alg != 1024 {
            let (name, trunc) = int_algorithm(data.int_alg)
                .or_else(|| (!data.int_name.is_empty()).then_some((data.int_name.as_str(), None)))
                .ok_or_else(unsupported)?;
            let alg_name = algorithm(name)?;
            let alg_key = data.int_key.to_vec();
            let alg_key_len = alg_key.len() as u32 * 8;
            nlas.push(match trunc {
                Some(alg_trunc_len) => Attr::AuthenticationAlgTrunc(packet::AlgAuth {
                    alg_name,
                    alg_key,
                    alg_key_len,
                    alg_trunc_len,
                }),
                None => Attr::AuthenticationAlg(packet::Alg {
                    alg_name,
                    alg_key,
                    alg_key_len,
                }),
            });
        }
        if data.encap {
            nlas.push(Attr::EncapsulationTemplate(packet::EncapTmpl {
                encap_type: packet::UDP_ENCAP_ESPINUDP,
                encap_sport: id.src.port,
                encap_dport: id.dst.port,
                encap_oa: packet::Address::default(),
            }));
        }
        if data.mark.value | data.mark.mask != 0 {
            nlas.push(Attr::MarkVal(data.mark.value));
            nlas.push(Attr::MarkMask(data.mark.mask));
        }
        if data.tfc != 0 {
            nlas.push(Attr::TfcPadding(data.tfc));
        }
        if data.esn || replay > 32 {
            let bmp = vec![0; (replay as usize).div_ceil(32)];
            nlas.push(Attr::ReplayStateEsn(packet::ReplayEsn {
                bmp_len: bmp.len() as u32,
                oseq: 0,
                seq: 0,
                oseq_hi: 0,
                seq_hi: 0,
                replay_window: replay,
                bmp,
            }));
        }
        if !data.inbound && [1, 3].contains(&data.copy_dscp) {
            nlas.push(Attr::ExtraFlags(1));
        }
        nlas.extend(id_attrs(id.mark, id.if_id));
        if self.sa_dir {
            nlas.push(direction(data.inbound));
        }
        let request = packet::state::ModifyMessage {
            user_sa_info: info,
            nlas,
        };
        Ok(if data.update {
            XfrmMessage::UpdateSa(request)
        } else {
            XfrmMessage::AddSa(request)
        })
    }

    pub fn add_sa(&mut self, id: &crate::model::SaId, data: &AddSa<'_>) -> io::Result<()> {
        if id.proto != 50 || id.if_id == 0 {
            return Err(unsupported());
        }
        if data.update && !self.owned(id) {
            return Err(missing());
        }
        let request = self.sa_message(id, data)?;
        let result = self.socket.ack(&message(NlmF::ACK, &request));
        match (result, request) {
            (Err(error), XfrmMessage::UpdateSa(sa))
                if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) =>
            {
                self.socket
                    .ack(&message(NlmF::ACK, &XfrmMessage::AddSa(sa)))?
            }
            (result, _) => result?,
        }
        self.sas.insert(id.key());
        self.allocations
            .remove(&(id.src.ip, id.dst.ip, id.spi, id.proto));
        Ok(())
    }
    fn read_sa(&mut self, id: &SaId) -> io::Result<packet::state::ModifyMessage> {
        if !self.owned(id) {
            return Err(missing());
        }
        self.socket
            .request(&message(
                NlmF::empty(),
                &XfrmMessage::GetSa(packet::state::DelGetMessage {
                    user_sa_id: sa_id(id),
                    nlas: id_attrs(id.mark, id.if_id),
                }),
            ))?
            .into_iter()
            .find(|reply| reply.kind == NEWSA)
            .ok_or_else(missing)
            .and_then(|reply| sa_reply(&reply))
    }
    pub fn query_sa(&mut self, id: &SaId) -> io::Result<(u64, u64, u64)> {
        let sa = self.read_sa(id)?;
        let last = if self.lastused {
            sa.nlas.iter().find_map(|attr| match attr {
                Attr::LastUsed(time) => Some(*time),
                _ => None,
            })
        } else {
            None
        }
        .unwrap_or(0);
        let lifetime = sa.user_sa_info.lifetime_cur;
        Ok((lifetime.bytes, lifetime.packets, monotonic_use_time(last)?))
    }
    fn delete_one(&mut self, id: &SaId) -> io::Result<()> {
        if !self.owned(id) {
            return Err(missing());
        }
        let request = XfrmMessage::DeleteSa(packet::state::DelGetMessage {
            user_sa_id: sa_id(id),
            nlas: id_attrs(id.mark, id.if_id),
        });
        match self.socket.ack(&message(NlmF::ACK, &request)) {
            Ok(()) => (),
            Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => (),
            Err(error) => return Err(error),
        }
        self.sas.remove(&id.key());
        self.allocations
            .remove(&(id.src.ip, id.dst.ip, id.spi, id.proto));
        Ok(())
    }
    pub fn delete_sa(&mut self, id: &crate::model::SaId) -> io::Result<()> {
        self.delete_one(id)
    }
    pub fn flush_sas(&mut self) -> io::Result<()> {
        // Never issue XFRM_MSG_FLUSHSA: there may be unrelated IPsec users.
        let ids: Vec<_> = self
            .sas
            .iter()
            .cloned()
            .chain(
                self.allocations
                    .iter()
                    .map(|(src, dst, spi, proto)| crate::model::SaId {
                        src: Host { ip: *src, port: 0 },
                        dst: Host { ip: *dst, port: 0 },
                        spi: *spi,
                        proto: *proto,
                        mark: Mark::default(),
                        if_id: 0,
                    }),
            )
            .collect();
        for id in ids {
            self.delete_one(&id)?;
        }
        Ok(())
    }
}
fn nonzero(v: u64) -> u64 {
    if v == 0 {
        u64::MAX
    } else {
        v
    }
}

pub struct LinuxPolicies {
    socket: Netlink,
}
impl LinuxPolicies {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            socket: Netlink::new(NlFamily::Xfrm)?,
        })
    }
    pub fn policy_key(id: &PolicyId) -> io::Result<PolicyKey> {
        // Use the same canonical networks, protocol and port masks as the
        // kernel request, without serializing a packet to identify a policy.
        let sel = selector(&id.src, &id.dst, "")?;
        Self::selector_key(&sel, id.dir, id.mark, id.if_id)
    }
    fn selector_key(
        sel: &packet::Selector,
        dir: u8,
        mark: Mark,
        if_id: u32,
    ) -> io::Result<PolicyKey> {
        Ok(PolicyKey {
            src: IpNet::new(host(sel.family, sel.saddr, 0)?.ip, sel.prefixlen_s)
                .map_err(|_| invalid())?,
            dst: IpNet::new(host(sel.family, sel.daddr, 0)?.ip, sel.prefixlen_d)
                .map_err(|_| invalid())?,
            src_port: sel.sport,
            src_port_mask: sel.sport_mask,
            dst_port: sel.dport,
            dst_port_mask: sel.dport_mask,
            protocol: sel.proto,
            dir,
            mark: Mark {
                value: mark.value & mark.mask,
                mask: mark.mask,
            },
            if_id,
        })
    }
    fn priorities(key: &PolicyKey, data: &PolicyData) -> (u32, u32) {
        let base = match data.prio {
            0 => 200000,
            3 => 600000,
            _ => 400000,
        };
        let auto = base
            - (key.src.prefix_len() as u32 + key.dst.prefix_len() as u32) * 512
            - if key.protocol != 0 { 256 } else { 0 }
            - (key.src_port_mask.count_ones() + key.dst_port_mask.count_ones()) * 4
            - u32::from(data.prio != 2);
        (
            if data.manual_prio == 0 {
                auto
            } else {
                data.manual_prio
            },
            auto,
        )
    }
    fn policy_spec(id: &PolicyId, data: &PolicyData) -> io::Result<packet::policy::ModifyMessage> {
        let info = packet::UserPolicyInfo {
            selector: selector(&id.src, &id.dst, "")?,
            priority: Self::priorities(&Self::policy_key(id)?, data).0,
            direction: id.dir,
            action: u8::from(data.kind == 3),
            ..Default::default()
        };
        let mut nlas = Vec::new();
        if data.kind == 1 && data.reqid != 0 {
            nlas.push(Attr::Template(vec![packet::UserTemplate {
                id: packet::Id {
                    daddr: packet::Address::from_ip(&data.dst.ip),
                    spi: if id.dir == 1 {
                        data.esp.unwrap_or(0)
                    } else {
                        0
                    },
                    proto: 50,
                },
                saddr: packet::Address::from_ip(&data.src.ip),
                family: data.src.family(),
                reqid: data.reqid,
                mode: packet::XFRM_MODE_TUNNEL,
                share: 0,
                optional: 0,
                aalgos: u32::MAX,
                ealgos: u32::MAX,
                calgos: u32::MAX,
            }]));
        }
        nlas.extend(id_attrs(id.mark, id.if_id));
        Ok(packet::policy::ModifyMessage {
            user_policy_info: info,
            nlas,
        })
    }
    fn policy_message(id: &PolicyId, data: &PolicyData, update: bool) -> io::Result<Message> {
        let request = Self::policy_spec(id, data)?;
        let request = if update {
            XfrmMessage::UpdatePolicy(request)
        } else {
            XfrmMessage::AddPolicy(request)
        };
        Ok(message(NlmF::ACK, &request))
    }
    fn policy_id(id: &PolicyId) -> io::Result<packet::policy::DelGetMessage> {
        Ok(packet::policy::DelGetMessage {
            user_policy_id: packet::UserPolicyId {
                selector: selector(&id.src, &id.dst, "")?,
                direction: id.dir,
                ..Default::default()
            },
            nlas: id_attrs(id.mark, id.if_id),
        })
    }
    fn delete_policy_message(id: &PolicyId) -> io::Result<Message> {
        Ok(message(
            NlmF::ACK,
            &XfrmMessage::DeletePolicy(Self::policy_id(id)?),
        ))
    }
    fn remove_kernel_policy(&self, id: &PolicyId) -> io::Result<()> {
        match self.socket.ack(&Self::delete_policy_message(id)?) {
            Ok(()) => Ok(()),
            Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
    fn policy_configuration(
        mut policy: packet::policy::ModifyMessage,
    ) -> packet::policy::ModifyMessage {
        policy.user_policy_info.index = 0;
        policy.user_policy_info.lifetime_cur = packet::Lifetime::default();
        // The kernel adds default policy type and may omit zero-valued
        // attributes. Attribute order and usage metadata are not configuration.
        policy.nlas.retain(|attr| match attr {
            Attr::PolicyType(value) => value.ptype != 0,
            Attr::Mark(value) => value.mask != 0,
            Attr::IfId(value) => *value != 0,
            Attr::Template(value) => !value.is_empty(),
            Attr::Pad() => false,
            _ => true,
        });
        for attr in &mut policy.nlas {
            if let Attr::Mark(mark) = attr {
                mark.value &= mark.mask;
            }
        }
        policy.nlas.sort_by_key(Nla::kind);
        policy
    }
}

impl PolicyKernel for LinuxPolicies {
    type Key = PolicyKey;
    type Inventory = HashMap<PolicyKey, packet::policy::ModifyMessage>;

    fn key(id: &PolicyId) -> io::Result<Self::Key> {
        Self::policy_key(id)
    }
    fn priority(id: &PolicyId, data: &PolicyData) -> io::Result<(u32, u32)> {
        Ok(Self::priorities(&Self::policy_key(id)?, data))
    }
    fn list_policies(&mut self) -> io::Result<Self::Inventory> {
        let request = XfrmMessage::GetPolicy(packet::policy::DelGetMessage::default());
        let mut inventory = HashMap::new();
        for reply in self.socket.request(&message(NlmF::DUMP, &request))? {
            if reply.kind != packet::XFRM_MSG_NEWPOLICY {
                continue;
            }
            let policy = packet::policy::ModifyMessage::parse(reply.payload.as_slice())
                .map_err(io::Error::other)?;
            let info = &policy.user_policy_info;
            // Our policies have no interface selector or security label and
            // use the main policy table. Other scopes remain foreign objects.
            if info.selector.ifindex != 0
                || info.selector.user != 0
                || policy.nlas.iter().any(|attr| {
                    matches!(
                        attr,
                        Attr::SecurityContext(_)
                            | Attr::PolicyType(packet::UserPolicyType { ptype: 1.., .. })
                    )
                })
            {
                continue;
            }
            let (mut mark, mut if_id) = (Mark::default(), 0);
            for attr in &policy.nlas {
                match attr {
                    Attr::Mark(value) => {
                        mark = Mark {
                            value: value.value,
                            mask: value.mask,
                        }
                    }
                    Attr::IfId(value) => if_id = *value,
                    _ => (),
                }
            }
            let key = Self::selector_key(&info.selector, info.direction, mark, if_id)?;
            inventory.insert(key, Self::policy_configuration(policy));
        }
        Ok(inventory)
    }
    fn policy_status(
        &self,
        inventory: &Self::Inventory,
        id: &PolicyId,
        data: &PolicyData,
    ) -> io::Result<PolicyStatus> {
        let Some(observed) = inventory.get(&Self::policy_key(id)?) else {
            return Ok(PolicyStatus::Missing);
        };
        let desired = Self::policy_configuration(Self::policy_spec(id, data)?);
        Ok(if *observed == desired {
            PolicyStatus::Matching
        } else {
            PolicyStatus::Changed
        })
    }
    fn write_policy(&mut self, id: &PolicyId, data: &PolicyData, replace: bool) -> io::Result<()> {
        self.socket.ack(&Self::policy_message(id, data, replace)?)
    }
    fn delete_policy(&mut self, id: &PolicyId) -> io::Result<()> {
        self.remove_kernel_policy(id)
    }
    fn query_policy(&mut self, id: &PolicyId) -> io::Result<u64> {
        let request = XfrmMessage::GetPolicy(Self::policy_id(id)?);
        let reply = self
            .socket
            .request(&message(NlmF::empty(), &request))?
            .into_iter()
            .find(|reply| reply.kind == packet::XFRM_MSG_NEWPOLICY)
            .ok_or_else(missing)?;
        let policy = packet::policy::ModifyMessage::parse(reply.payload.as_slice())
            .map_err(io::Error::other)?;
        monotonic_use_time(policy.user_policy_info.lifetime_cur.use_time)
    }
}

impl Xfrm {
    pub fn event(
        &mut self,
        message: &Reply,
        policies: &Policies<LinuxPolicies>,
    ) -> io::Result<Option<rpc::Event>> {
        let bytes = &message.payload;
        let mut event = rpc::Event {
            kind: rpc::Event_kind::ready,
            expiry: None,
            acquire: None,
            mapping: None,
            addressChanged: None,
        };
        match message.kind {
            packet::XFRM_MSG_ACQUIRE => {
                let packet::AcquireMessage { acquire, nlas } =
                    packet::AcquireMessage::parse(bytes.as_slice()).map_err(io::Error::other)?;
                let reqid = nlas
                    .iter()
                    .find_map(|attr| match attr {
                        Attr::Template(templates) => {
                            templates.first().map(|template| template.reqid)
                        }
                        _ => None,
                    })
                    .unwrap_or(0);
                let if_id = nlas
                    .iter()
                    .find_map(|attr| match attr {
                        Attr::IfId(id) => Some(*id),
                        _ => None,
                    })
                    .unwrap_or(0);
                if !policies.contains_reqid(if_id, reqid) {
                    return Ok(None);
                }
                event.kind = rpc::Event_kind::acquire;
                event.acquire = Some(rpc::Acquire {
                    reqid: reqid.into(),
                    src: rpc_selector(selector_ts(&acquire.selector, true)?),
                    dst: rpc_selector(selector_ts(&acquire.selector, false)?),
                    sequence: acquire.seq.into(),
                });
            }
            packet::XFRM_MSG_EXPIRE => {
                // ExpireMessage omits trailing attributes in this crate version.
                // Parse its typed fixed record and use the crate's NLA parser
                // for the interface ID and mark needed to identify our SA.
                let expire = packet::UserExpire::parse(bytes).map_err(io::Error::other)?;
                let sa = expire.state;
                let dst = host(sa.family, sa.id.daddr, 0)?;
                let src = host(sa.family, sa.saddr, 0)?;
                let mut mark = Mark::default();
                let mut if_id = 0;
                for nla in NlasIterator::new(&bytes[expire.buffer_len()..]) {
                    let attr =
                        Attr::parse(&nla.map_err(io::Error::other)?).map_err(io::Error::other)?;
                    match attr {
                        Attr::IfId(id) => if_id = id,
                        Attr::Mark(value) => {
                            mark = Mark {
                                value: value.value,
                                mask: value.mask,
                            }
                        }
                        _ => (),
                    }
                }
                let id = SaId {
                    src,
                    dst: dst.clone(),
                    spi: sa.id.spi,
                    proto: sa.id.proto,
                    mark,
                    if_id,
                }
                .key();
                if !self.sas.contains(&id) {
                    return Ok(None);
                }
                let hard = expire.hard != 0;
                if hard {
                    self.sas.remove(&id);
                }
                event.kind = rpc::Event_kind::expire;
                event.expiry = Some(rpc::Expiry {
                    protocol: sa.id.proto.into(),
                    spi: sa.id.spi.into(),
                    destination: endpoint(dst),
                    hard,
                });
            }
            packet::XFRM_MSG_MAPPING => {
                let mapping = packet::UserMapping::parse(bytes).map_err(io::Error::other)?;
                let spi = mapping.id.spi;
                let family = mapping.id.family;
                let dst = host(family, mapping.id.daddr, 0)?;
                if mapping.id.proto != 50
                    || !self
                        .sas
                        .iter()
                        .any(|id| id.dst.ip == dst.ip && id.spi == spi && id.proto == 50)
                {
                    return Ok(None);
                }
                let remote = host(family, mapping.new_saddr, mapping.new_sport)?;
                event.kind = rpc::Event_kind::mapping;
                event.mapping = Some(rpc::Mapping {
                    spi: spi.into(),
                    destination: endpoint(dst),
                    remote: endpoint(remote),
                });
            }
            _ => return Ok(None),
        }
        Ok(Some(event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specific_icmp_codes_outrank_type_only_policies() {
        for (address, protocol, icmp_type) in [("0.0.0.0", 1, 3), ("::", 58, 128)] {
            let any = Host {
                ip: address.parse().unwrap(),
                port: 0,
            };
            let mut id = PolicyId {
                src: Ts::from_subnet(any.clone(), 0, protocol, icmp_type << 8, icmp_type << 8)
                    .unwrap(),
                dst: Ts::from_subnet(any.clone(), 0, 0, 0, u16::MAX).unwrap(),
                dir: 1,
                mark: Mark::default(),
                if_id: 41,
            };
            let data = PolicyData {
                kind: 1,
                prio: 1,
                manual_prio: 0,
                src: any.clone(),
                dst: any,
                reqid: 42,
                policy_count: 1,
                esp: Some(0x10203),
            };
            let priority = |id: &PolicyId| {
                let request = LinuxPolicies::policy_message(id, &data, false).unwrap();
                packet::policy::ModifyMessage::parse(request.payload.as_slice())
                    .unwrap()
                    .user_policy_info
                    .priority
            };
            let broad = priority(&id);
            id.src.from_port += 1;
            id.src.to_port += 1;
            assert!(priority(&id) < broad, "ICMP code must increase specificity");
        }
    }

    #[test]
    fn policy_keys_follow_canonical_kernel_selectors() {
        for (network, first, last, prefix) in [
            ("10.1.0.0", "10.1.0.1", "10.1.0.254", 24),
            ("2001:db8::", "2001:db8::1", "2001:db8::fffe", 112),
        ] {
            let host = Host {
                ip: network.parse().unwrap(),
                port: 0,
            };
            let id = PolicyId {
                src: Ts::from_subnet(host.clone(), prefix, 6, 1024, 2047).unwrap(),
                dst: Ts::from_subnet(host, prefix, 0, 0, u16::MAX).unwrap(),
                dir: 1,
                mark: Mark {
                    value: 0x42,
                    mask: 0xff,
                },
                if_id: 41,
            };
            let keys = HashSet::from([LinuxPolicies::policy_key(&id).unwrap()]);
            // The kernel sees the same prefixes, aligned port range and
            // protocol even though the caller's traffic selectors differ.
            let mut equivalent = id.clone();
            equivalent.src.from.ip = first.parse().unwrap();
            equivalent.src.to.ip = last.parse().unwrap();
            equivalent.src.from.port = 123;
            equivalent.src.from_port = 1025;
            equivalent.src.to_port = 2046;
            equivalent.src.proto = 0;
            equivalent.dst.proto = 6;
            equivalent.mark.value = 0x1000042;
            assert!(keys.contains(&LinuxPolicies::policy_key(&equivalent).unwrap()));

            let mut different = id.clone();
            different.src.to_port = 4095;
            assert!(!keys.contains(&LinuxPolicies::policy_key(&different).unwrap()));
            different = id.clone();
            different.dir = 2;
            assert!(!keys.contains(&LinuxPolicies::policy_key(&different).unwrap()));
            different = id.clone();
            different.if_id += 1;
            assert!(!keys.contains(&LinuxPolicies::policy_key(&different).unwrap()));
            different = id.clone();
            different.mark.mask = 0xffff;
            assert!(!keys.contains(&LinuxPolicies::policy_key(&different).unwrap()));
        }
    }

    #[test]
    fn icmp_selectors_use_packet_byte_order() {
        for (address, prefix, protocol, type_code) in
            [("10.1.0.0", 24, 1, 0x0800), ("2001:db8::", 64, 58, 0x8001)]
        {
            let host = Host {
                ip: address.parse().unwrap(),
                port: 0,
            };
            let src =
                Ts::from_subnet(host.clone(), prefix, protocol, type_code, type_code).unwrap();
            let dst = Ts::from_subnet(host, prefix, 0, 0, u16::MAX).unwrap();
            let selector = selector(&src, &dst, "").unwrap();
            assert_eq!(selector.sport, type_code >> 8);
            assert_eq!(selector.dport, type_code & 0xff);
            let mut bytes = vec![0; selector.buffer_len()];
            selector.emit(&mut bytes);
            let parsed = packet::Selector::parse(&bytes).unwrap();
            for source in [false, true] {
                let decoded = selector_ts(&parsed, source).unwrap();
                assert_eq!(decoded.from.ip, src.from.ip);
                assert_eq!(decoded.from_port, type_code);
                assert_eq!(decoded.to_port, type_code);
            }

            let mut id = PolicyId {
                src,
                dst,
                dir: 1,
                mark: Mark::default(),
                if_id: 41,
            };
            let keys = HashSet::from([LinuxPolicies::policy_key(&id).unwrap()]);
            // strongSwan may put the same ICMP type/code on either selector.
            std::mem::swap(&mut id.src, &mut id.dst);
            assert!(keys.contains(&LinuxPolicies::policy_key(&id).unwrap()));
            id.dst.from_port += 1;
            id.dst.to_port += 1;
            assert!(!keys.contains(&LinuxPolicies::policy_key(&id).unwrap()));
        }
    }
}
