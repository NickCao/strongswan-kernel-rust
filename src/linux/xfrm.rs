// SPDX-License-Identifier: GPL-2.0-or-later
// SA semantics ported from kernel_netlink_ipsec.c (Martin Willi,
// Tobias Brunner and contributors; Copyright secunet Security Networks AG).
// Packet layouts and serialization are supplied by netlink-packet-xfrm.
use super::{
    iptfs,
    netlink::{Message, Netlink, NlFamily, NlmF, Reply},
    policy::LinuxPolicies,
};
use crate::rpc_api::algorithms::{encryption as enc, integrity as auth};
use crate::sa::{is_missing, ObservedSa, SaHandle as _, SaKernel, SaSpec, SaState, SaUsage, Sas};
use crate::{backend::rpc_selector, error::invalid, model::*, policy::Policies, rpc_api as rpc};
use netlink_packet_core::{DefaultNla, Emitable, Nla, NlasIterator, Parseable};
use netlink_packet_xfrm::{self as packet, XfrmAttrs as Attr, XfrmMessage};
use rustix::net::ipproto;
use std::io;

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
pub(super) fn host(family: u16, address: packet::Address, port: u16) -> io::Result<Endpoint> {
    let ip = match family as i32 {
        libc::AF_INET => address.to_ipv4().into(),
        libc::AF_INET6 => address.to_ipv6().into(),
        _ => return Err(invalid()),
    };
    Ok(Endpoint::new(ip, port))
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
        daddr: packet::Address::from_ip(&id.dst.address),
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
    let (port, mask) = if [ipproto::ICMP, ipproto::ICMPV6]
        .iter()
        .any(|protocol| protocol.as_raw().get() == u32::from(selector.proto))
    {
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
        enc::DES => ("des", None),
        enc::TRIPLE_DES => ("des3_ede", None),
        enc::CAST => ("cast5", None),
        enc::BLOWFISH => ("blowfish", None),
        enc::NULL => ("cipher_null", None),
        enc::AES_CBC => ("cbc(aes)", None),
        enc::AES_CTR => ("rfc3686(ctr(aes))", None),
        enc::AES_CCM_ICV8 => ("rfc4309(ccm(aes))", Some(64)),
        enc::AES_CCM_ICV12 => ("rfc4309(ccm(aes))", Some(96)),
        enc::AES_CCM_ICV16 => ("rfc4309(ccm(aes))", Some(128)),
        enc::AES_GCM_ICV8 => ("rfc4106(gcm(aes))", Some(64)),
        enc::AES_GCM_ICV12 => ("rfc4106(gcm(aes))", Some(96)),
        enc::AES_GCM_ICV16 => ("rfc4106(gcm(aes))", Some(128)),
        enc::NULL_AUTH_AES_GMAC => ("rfc4543(gcm(aes))", Some(128)),
        enc::CAMELLIA_CBC => ("cbc(camellia)", None),
        enc::CHACHA20_POLY1305 => ("rfc7539esp(chacha20,poly1305)", Some(128)),
        enc::SERPENT_CBC => ("serpent", None),
        enc::TWOFISH_CBC => ("twofish", None),
        _ => return None,
    })
}
fn int_algorithm(id: u16) -> Option<(&'static str, Option<u32>)> {
    Some(match id {
        auth::HMAC_MD5_96 => ("md5", None),
        auth::HMAC_SHA1_96 => ("sha1", None),
        auth::AES_XCBC_96 => ("xcbc(aes)", Some(96)),
        auth::HMAC_MD5_128 => ("hmac(md5)", Some(128)),
        auth::HMAC_SHA1_160 => ("hmac(sha1)", Some(160)),
        auth::AES_CMAC_96 => ("cmac(aes)", Some(96)),
        auth::HMAC_SHA2_256_128 => ("hmac(sha256)", Some(128)),
        auth::HMAC_SHA2_384_192 => ("hmac(sha384)", Some(192)),
        auth::HMAC_SHA2_512_256 => ("hmac(sha512)", Some(256)),
        auth::HMAC_SHA2_256_96 => ("sha256", None),
        auth::HMAC_SHA2_256_256 => ("hmac(sha256)", Some(256)),
        auth::HMAC_SHA2_384_384 => ("hmac(sha384)", Some(384)),
        auth::HMAC_SHA2_512_512 => ("hmac(sha512)", Some(512)),
        _ => return None,
    })
}

pub struct LinuxSas {
    socket: Netlink,
    pub sa_dir: bool,
    pub lastused: bool,
    iptfs: rpc::IptfsConfig,
}
impl LinuxSas {
    pub fn new(iptfs: rpc::IptfsConfig) -> io::Result<Self> {
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
            sa_dir: version >= (6, 10),
            lastused: version >= (6, 2),
            iptfs,
        })
    }
    fn feature_flags(&self) -> u32 {
        KERNEL_ESP_V3_TFC
            | KERNEL_REQUIRE_UDP_ENCAPSULATION
            | KERNEL_POLICY_SPI
            | KERNEL_ACQUIRE_SEQ
            | if self.lastused { KERNEL_SA_USE_TIME } else { 0 }
    }
    fn allocate_spi(
        &mut self,
        src: &Endpoint,
        dst: &Endpoint,
        proto: u8,
        min: u32,
        max: u32,
    ) -> io::Result<u32> {
        if src.family() != dst.family()
            || proto != ipproto::ESP.as_raw().get() as u8
            || min == 0
            || min > max
        {
            return Err(invalid());
        }
        let request = XfrmMessage::AllocSpi(packet::state::AllocSpiMessage {
            spi_info: packet::UserSpiInfo {
                info: packet::UserSaInfo {
                    saddr: packet::Address::from_ip(&src.address),
                    id: packet::Id {
                        daddr: packet::Address::from_ip(&dst.address),
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
                return Ok(spi);
            }
        }
        Err(invalid())
    }
    fn sa_message(&self, id: &SaId, data: &SaConfig) -> io::Result<XfrmMessage> {
        let mode = TunnelMode::try_from(data.mode)?;
        if mode == TunnelMode::Iptfs && data.tfc != 0 {
            return Err(unsupported());
        }
        // strongSwan has already jittered the rekey limits. Tunnel selectors
        // are represented by policies, not installed on the SA itself.
        let lifetime = data.lifetime.as_ref().ok_or_else(invalid)?;
        let mut flags = packet::XFRM_STATE_AF_UNSPEC;
        if !data.copy_ecn {
            flags |= packet::XFRM_STATE_NOECN;
        }
        if data.inbound && data.forward_icmp {
            flags |= packet::XFRM_STATE_ICMP;
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
            saddr: packet::Address::from_ip(&id.src.address),
            id: packet::Id {
                daddr: packet::Address::from_ip(&id.dst.address),
                spi: id.spi,
                proto: id.proto,
            },
            family: id.src.family(),
            mode: iptfs::mode(mode),
            reqid: data.reqid,
            seq: data.acquire_sequence,
            flags,
            replay_window: if !data.esn && replay <= 32 {
                replay as u8
            } else {
                0
            },
            lifetime_cfg: packet::LifetimeConfig {
                soft_byte_limit: nonzero(lifetime.bytes.rekey),
                hard_byte_limit: nonzero(lifetime.bytes.life),
                soft_packet_limit: nonzero(lifetime.packets.rekey),
                hard_packet_limit: nonzero(lifetime.packets.life),
                soft_add_expires_seconds: lifetime.time.rekey,
                hard_add_expires_seconds: lifetime.time.life,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut nlas = Vec::new();
        if data.encryption.id != enc::UNDEFINED {
            let (name, icv) = enc_algorithm(data.encryption.id)
                .or_else(|| {
                    (!data.encryption.name.is_empty())
                        .then_some((data.encryption.name.as_str(), None))
                })
                .ok_or_else(unsupported)?;
            let alg_name = algorithm(name)?;
            let alg_key = data.encryption.key.to_vec();
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
        if data.integrity.id != auth::UNDEFINED {
            let (name, trunc) = int_algorithm(data.integrity.id)
                .or_else(|| {
                    (!data.integrity.name.is_empty())
                        .then_some((data.integrity.name.as_str(), None))
                })
                .ok_or_else(unsupported)?;
            let alg_name = algorithm(name)?;
            let alg_key = data.integrity.key.to_vec();
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
        if data.udp_encapsulation {
            nlas.push(Attr::EncapsulationTemplate(packet::EncapTmpl {
                encap_type: packet::UDP_ENCAP_ESPINUDP,
                encap_sport: id.src.port,
                encap_dport: id.dst.port,
                encap_oa: packet::Address::default(),
            }));
        }
        if data.output_mark.value | data.output_mark.mask != 0 {
            nlas.push(Attr::MarkVal(data.output_mark.value));
            nlas.push(Attr::MarkMask(data.output_mark.mask));
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
            nlas.push(Attr::ExtraFlags(packet::XFRM_SA_XFLAG_DONT_ENCAP_DSCP));
        }
        nlas.extend(id_attrs(id.mark, id.if_id));
        if self.sa_dir {
            nlas.push(direction(data.inbound));
        }
        if mode == TunnelMode::Iptfs {
            nlas.extend(iptfs::attributes(
                &self.iptfs,
                data.inbound,
                data.iptfs_dont_fragment,
            ));
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

    fn read(&mut self, id: &SaId) -> io::Result<packet::state::ModifyMessage> {
        self.socket
            .request(&message(
                NlmF::empty(),
                &XfrmMessage::GetSa(native_request(id)),
            ))?
            .into_iter()
            .find(|reply| reply.kind == NEWSA)
            .ok_or_else(missing)
            .and_then(|reply| sa_reply(&reply))
    }
    fn observe(
        &self,
        mut sa: packet::state::ModifyMessage,
    ) -> io::Result<ObservedSa<SaHandle, Configuration>> {
        let info = &sa.user_sa_info;
        let mut mark = Mark::default();
        let mut if_id = 0;
        for attr in &sa.nlas {
            match attr {
                Attr::IfId(value) => if_id = *value,
                Attr::Mark(value) => {
                    mark = Mark {
                        value: value.value & value.mask,
                        mask: value.mask,
                    }
                }
                _ => (),
            }
        }
        let id = SaId {
            src: host(info.family, info.saddr, 0)?,
            dst: host(info.family, info.id.daddr, 0)?,
            spi: info.id.spi,
            proto: info.id.proto,
            mark,
            if_id,
        };
        let has_transform = sa.nlas.iter().any(|attr| {
            matches!(
                attr,
                Attr::EncryptionAlg(_)
                    | Attr::EncryptionAlgAead(_)
                    | Attr::AuthenticationAlg(_)
                    | Attr::AuthenticationAlgTrunc(_)
                    | Attr::CompressionAlg(_)
            )
        });
        let state = if has_transform {
            SaState::Installed
        } else if info.seq != 0 || info.id.spi == 0 {
            SaState::Acquiring
        } else {
            SaState::Larval
        };
        let last = if self.lastused {
            sa.nlas
                .iter()
                .find_map(|attr| match attr {
                    Attr::LastUsed(value) => Some(*value),
                    _ => None,
                })
                .unwrap_or(0)
        } else {
            0
        };
        let usage = SaUsage {
            bytes: info.lifetime_cur.bytes,
            packets: info.lifetime_cur.packets,
            last_use: monotonic_use_time(last)?,
        };
        let created_at = info.lifetime_cur.add_time;
        let supported = state == SaState::Installed
            && iptfs::observed_mode(info.mode).is_some()
            && id.proto == ipproto::ESP.as_raw().get() as u8;
        // Keep static settings only. The kernel's canonical representation
        // resolves algorithm aliases/default ICV lengths at first installation.
        // Subsequent inventories never change that desired snapshot.
        sa.user_sa_info.lifetime_cur = Default::default();
        sa.user_sa_info.stats = Default::default();
        sa.user_sa_info.seq = 0;
        sa.nlas.retain_mut(|attr| match attr {
            // AUTH is a redundant compatibility copy of AUTH_TRUNC in dumps.
            Attr::AuthenticationAlg(_)
            | Attr::ReplayState(_)
            | Attr::LastUsed(_)
            | Attr::LifetimeBytes(_)
            | Attr::ReplayThreshold(_)
            | Attr::EventTimeThreshold(_)
            | Attr::MappingTimeThreshold(_)
            | Attr::Pad() => false,
            Attr::ReplayStateEsn(replay) => {
                replay.seq = 0;
                replay.oseq = 0;
                replay.seq_hi = 0;
                replay.oseq_hi = 0;
                replay.bmp.fill(0);
                true
            }
            _ => true,
        });
        sa.nlas.sort_by_key(Nla::kind);
        Ok(ObservedSa {
            handle: SaHandle(id),
            state,
            created_at,
            usage,
            config: supported.then_some(Configuration(sa)),
        })
    }
}

/// Opaque native key: unlike policies, Linux SAs have no assigned index.
/// SPI protocols use destination/SPI/protocol/family/mark; address-based
/// transforms additionally require the source address. if_id is configuration,
/// not a distinct GETSA/DELSA lookup namespace.
pub struct SaHandle(SaId);
impl crate::sa::SaHandle for SaHandle {
    fn id(&self) -> &SaId {
        &self.0
    }
}

/// Static canonical settings only. No Debug implementation: this includes keys.
#[derive(PartialEq, Eq)]
pub struct Configuration(packet::state::ModifyMessage);

fn native_request(id: &SaId) -> packet::state::DelGetMessage {
    let mut nlas = id_attrs(id.mark, 0);
    if ![ipproto::ESP, ipproto::AH, ipproto::COMP]
        .iter()
        .any(|protocol| protocol.as_raw().get() == u32::from(id.proto))
    {
        nlas.push(Attr::SrcAddr(packet::Address::from_ip(&id.src.address)));
    }
    packet::state::DelGetMessage {
        user_sa_id: sa_id(id),
        nlas,
    }
}

impl SaKernel for LinuxSas {
    type Handle = SaHandle;
    type Config = Configuration;
    fn features(&self) -> u32 {
        self.feature_flags()
    }
    fn allocate(
        &mut self,
        src: &Endpoint,
        dst: &Endpoint,
        proto: u8,
        min: u32,
        max: u32,
    ) -> io::Result<u32> {
        self.allocate_spi(src, dst, proto, min, max)
    }
    fn list(&mut self) -> io::Result<Vec<ObservedSa<SaHandle, Configuration>>> {
        // A GETSA dump takes only optional filter attributes, not the fixed
        // usersa_id record required for a single-object GETSA request.
        let replies = self.socket.request(&Message {
            kind: packet::XFRM_MSG_GETSA,
            flags: NlmF::DUMP,
            payload: Vec::new(),
        })?;
        replies
            .iter()
            .filter(|reply| reply.kind == NEWSA)
            .map(|reply| self.observe(sa_reply(reply)?))
            .collect()
    }
    fn get(&mut self, id: &SaId) -> io::Result<ObservedSa<SaHandle, Configuration>> {
        let sa = self.read(id)?;
        self.observe(sa)
    }
    fn create(&mut self, spec: &SaSpec<'_>) -> io::Result<ObservedSa<SaHandle, Configuration>> {
        if spec.id.proto != ipproto::ESP.as_raw().get() as u8 || spec.id.if_id == 0 {
            return Err(unsupported());
        }
        let mut request = self.sa_message(spec.id, spec.config)?;
        if spec.config.update {
            // UPDSA is only for maturation of a larval reservation. In
            // particular, never apply it to an already established SA.
            match self.get(spec.id) {
                Ok(current) if current.state != SaState::Installed => (),
                Ok(_) => return Err(io::Error::from_raw_os_error(libc::EEXIST)),
                Err(error) if is_missing(&error) => {
                    if let XfrmMessage::UpdateSa(sa) = request {
                        request = XfrmMessage::AddSa(sa);
                    }
                }
                Err(error) => return Err(error),
            }
        }
        match self.socket.ack(&message(NlmF::ACK, &request)) {
            Err(error) if is_missing(&error) && spec.config.update => {
                // It may expire between GETSA and the maturation request.
                // The controller has verified this is still first installation.
                if let XfrmMessage::UpdateSa(sa) = request {
                    self.socket
                        .ack(&message(NlmF::ACK, &XfrmMessage::AddSa(sa)))?;
                } else {
                    return Err(error);
                }
            }
            result => result?,
        }
        self.get(spec.id)
    }
    fn delete(&mut self, handle: &SaHandle) -> io::Result<()> {
        match self.socket.ack(&message(
            NlmF::ACK,
            &XfrmMessage::DeleteSa(native_request(handle.id())),
        )) {
            Err(error) if is_missing(&error) => Ok(()),
            result => result,
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.socket.ack(&message(
            NlmF::ACK,
            &XfrmMessage::FlushSa(packet::state::FlushMessage::default()),
        ))
    }
}

fn nonzero(v: u64) -> u64 {
    if v == 0 {
        u64::MAX
    } else {
        v
    }
}

pub fn event(
    message: &Reply,
    sas: &mut Sas<LinuxSas>,
    policies: &Policies<LinuxPolicies>,
) -> io::Result<Option<rpc::Event>> {
    let bytes = &message.payload;
    let mut event = rpc::Event {
        kind: match message.kind {
            packet::XFRM_MSG_ACQUIRE => rpc::EventKind::Acquire,
            packet::XFRM_MSG_EXPIRE => rpc::EventKind::Expire,
            packet::XFRM_MSG_MAPPING => rpc::EventKind::Mapping,
            _ => return Ok(None),
        },
        expiry: None,
        acquire: None,
        mapping: None,
        address_changed: None,
    };
    match message.kind {
        packet::XFRM_MSG_ACQUIRE => {
            let packet::AcquireMessage { acquire, nlas } =
                packet::AcquireMessage::parse(bytes.as_slice()).map_err(io::Error::other)?;
            let reqid = nlas
                .iter()
                .find_map(|attr| match attr {
                    Attr::Template(templates) => templates.first().map(|template| template.reqid),
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
            event.kind = rpc::EventKind::Acquire;
            event.acquire = Some(rpc::Acquire {
                reqid,
                src: rpc_selector(selector_ts(&acquire.selector, true)?),
                dst: rpc_selector(selector_ts(&acquire.selector, false)?),
                sequence: acquire.seq,
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
                dst,
                spi: sa.id.spi,
                proto: sa.id.proto,
                mark,
                if_id,
            }
            .key();
            let hard = expire.hard != 0;
            if !sas.expire(&id, hard) {
                return Ok(None);
            }
            event.kind = rpc::EventKind::Expire;
            event.expiry = Some(rpc::Expiry {
                protocol: sa.id.proto,
                spi: sa.id.spi,
                destination: dst,
                hard,
            });
        }
        packet::XFRM_MSG_MAPPING => {
            let mapping = packet::UserMapping::parse(bytes).map_err(io::Error::other)?;
            let spi = mapping.id.spi;
            let family = mapping.id.family;
            let dst = host(family, mapping.id.daddr, 0)?;
            if mapping.id.proto != ipproto::ESP.as_raw().get() as u8
                || !sas.ids().any(|id| {
                    id.dst.address == dst.address
                        && id.spi == spi
                        && id.proto == ipproto::ESP.as_raw().get() as u8
                })
            {
                return Ok(None);
            }
            let remote = host(family, mapping.new_saddr, mapping.new_sport)?;
            event.kind = rpc::EventKind::Mapping;
            event.mapping = Some(rpc::Mapping {
                spi,
                destination: dst,
                remote,
            });
        }
        _ => return Ok(None),
    }
    Ok(Some(event))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_ignore_packet_state_but_detect_managed_configuration_drift() {
        let backend = LinuxSas::new(Default::default()).unwrap();
        let sa = packet::state::ModifyMessage {
            user_sa_info: packet::UserSaInfo {
                family: libc::AF_INET as u16,
                saddr: packet::Address::from_ip(&"192.0.2.1".parse().unwrap()),
                id: packet::Id {
                    daddr: packet::Address::from_ip(&"192.0.2.2".parse().unwrap()),
                    spi: 0x10203,
                    proto: 50,
                },
                mode: packet::XFRM_MODE_TUNNEL,
                reqid: 42,
                ..Default::default()
            },
            nlas: vec![
                Attr::EncryptionAlgAead(packet::AlgAead {
                    alg_name: algorithm("rfc4106(gcm(aes))").unwrap(),
                    alg_key: vec![0; 20],
                    alg_key_len: 160,
                    alg_icv_len: 128,
                }),
                Attr::IfId(41),
                Attr::ReplayStateEsn(packet::ReplayEsn {
                    bmp_len: 4,
                    replay_window: 128,
                    bmp: vec![0; 4],
                    ..Default::default()
                }),
            ],
        };
        let expected = backend.observe(sa.clone()).unwrap().config;
        let mut running = sa.clone();
        running.user_sa_info.lifetime_cur.bytes = 1000;
        running.user_sa_info.lifetime_cur.packets = 10;
        running.user_sa_info.stats.replay = 2;
        running.user_sa_info.seq = 123;
        running.nlas.push(Attr::LastUsed(0));
        running.nlas.push(Attr::ReplayThreshold(10));
        if let Attr::ReplayStateEsn(replay) = &mut running.nlas[2] {
            replay.seq = 9;
            replay.oseq = 12;
            replay.seq_hi = 1;
            replay.oseq_hi = 2;
            replay.bmp.fill(u32::MAX);
        }
        running.nlas.reverse();
        let observed = backend.observe(running).unwrap();
        assert!(observed.config == expected);
        assert_eq!(observed.usage.packets, 10);
        for mutation in 0..6 {
            let mut drifted = sa.clone();
            match mutation {
                0 => drifted.user_sa_info.reqid += 1,
                1 => drifted.user_sa_info.flags ^= packet::XFRM_STATE_NOECN,
                2 => drifted.user_sa_info.lifetime_cfg.hard_add_expires_seconds = 100,
                3 => {
                    if let Attr::EncryptionAlgAead(algorithm) = &mut drifted.nlas[0] {
                        algorithm.alg_key[0] = 1;
                    }
                }
                4 => {
                    if let Attr::ReplayStateEsn(replay) = &mut drifted.nlas[2] {
                        replay.replay_window = 64;
                    }
                }
                _ => drifted.nlas.push(Attr::MarkVal(999)),
            }
            assert!(backend.observe(drifted).unwrap().config != expected);
        }
    }
}
