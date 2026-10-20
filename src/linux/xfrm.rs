// SPDX-License-Identifier: GPL-2.0-or-later
// SA semantics ported from kernel_netlink_ipsec.c (Martin Willi,
// Tobias Brunner and contributors; Copyright secunet Security Networks AG).
// Packet layouts and serialization are supplied by netlink-packet-xfrm.
use super::{
    netlink::{Message, Netlink, NlFamily, NlmF, Reply},
    policy::LinuxPolicies,
};
use crate::{
    backend::{endpoint, rpc_selector},
    error::invalid,
    model::*,
    policy::Policies,
    rpc_api as rpc,
};
use netlink_packet_core::{DefaultNla, Emitable, NlasIterator, Parseable};
use netlink_packet_xfrm::{self as packet, XfrmAttrs as Attr, XfrmMessage};
use std::{collections::HashSet, io, net::IpAddr};

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

pub(super) fn missing() -> io::Error {
    io::Error::from_raw_os_error(libc::ENOENT)
}
fn unsupported() -> io::Error {
    io::Error::from_raw_os_error(libc::EOPNOTSUPP)
}
pub(super) fn monotonic_use_time(time: u64) -> io::Result<u64> {
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
pub(super) fn message(flags: NlmF, value: &XfrmMessage) -> Message {
    Message::new(value.message_type(), flags, value)
}
pub(super) fn host(family: u16, address: packet::Address, port: u16) -> io::Result<Host> {
    let ip = match family as i32 {
        libc::AF_INET => address.to_ipv4().into(),
        libc::AF_INET6 => address.to_ipv6().into(),
        _ => return Err(invalid()),
    };
    Ok(Host { ip, port })
}
pub(super) fn id_attrs(mark: Mark, if_id: u32) -> Vec<Attr> {
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
pub(super) fn selector_ts(selector: &packet::Selector, source: bool) -> io::Result<Ts> {
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
        // strongSwan's RPC flush removes only this session's tracked states.
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
    /// Orderly daemon shutdown owns the entire namespace's XFRM state table,
    /// including larval reservations and states absent from our bookkeeping.
    pub fn flush_all_sas(&mut self) -> io::Result<()> {
        self.socket.ack(&message(
            NlmF::ACK,
            &XfrmMessage::FlushSa(packet::state::FlushMessage::default()),
        ))?;
        self.sas.clear();
        self.allocations.clear();
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
