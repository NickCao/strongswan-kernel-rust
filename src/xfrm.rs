// SPDX-License-Identifier: GPL-2.0-or-later
// Ported from kernel_netlink_ipsec.c (Martin Willi, Tobias Brunner and
// contributors; Copyright secunet Security Networks AG).
use crate::model::PolicyId;
use crate::{
    backend::{endpoint, rpc_selector},
    error::invalid,
    model::*,
    netlink::{self, Message, Netlink, NlFamily, NlmF, Reply},
    rpc_api as rpc,
    uapi::*,
};
use std::{
    collections::{HashMap, HashSet},
    io,
    mem::{offset_of as off, size_of},
    net::IpAddr,
};
use zeroize::Zeroizing;

pub const NEWSA: u16 = 16;
const DELSA: u16 = 17;
const GETSA: u16 = 18;
const NEWPOLICY: u16 = 19;
const DELPOLICY: u16 = 20;
const GETPOLICY: u16 = 21;
const ALLOCSPI: u16 = 22;
const UPDPOLICY: u16 = 25;
const UPDSA: u16 = 26;
const AUTH: u16 = 1;
const CRYPT: u16 = 2;
const ENCAP: u16 = 4;
const TMPL: u16 = 5;
const LASTUSED: u16 = 15;
const AEAD: u16 = 18;
const AUTH_TRUNC: u16 = 20;
const MARK: u16 = 21;
const REPLAY_ESN: u16 = 23;
const IF_ID: u16 = 31;
const SA_DIR: u16 = 33;

fn missing() -> io::Error {
    io::Error::from_raw_os_error(libc::ENOENT)
}
fn unsupported() -> io::Error {
    io::Error::from_raw_os_error(libc::EOPNOTSUPP)
}
pub fn selector(src: &Ts, dst: &Ts, interface: &str) -> io::Result<Vec<u8>> {
    if src.from.family() != dst.from.family() {
        return Err(invalid());
    }
    let mut b = buffer::<Selector>();
    let (src_net, src_prefix) = src.subnet();
    let (dst_net, dst_prefix) = dst.subnet();
    src_net.put(&mut b, off!(Selector, saddr));
    dst_net.put(&mut b, off!(Selector, daddr));
    b[off!(Selector, prefixlen_s)] = src_prefix;
    b[off!(Selector, prefixlen_d)] = dst_prefix;
    put16(&mut b, off!(Selector, family), src.from.family());
    b[off!(Selector, proto)] = src.proto.max(dst.proto);
    let (mut sport, mut smask) = src.ports();
    let (mut dport, mut dmask) = dst.ports();
    if [1, 58].contains(&b[off!(Selector, proto)]) && (sport != 0 || dport != 0) {
        let p = sport.max(dport);
        sport = p >> 8;
        dport = p & 0xff;
        smask = if sport == 0 { 0 } else { u16::MAX };
        dmask = if dport == 0 { 0 } else { u16::MAX };
    }
    for (offset, value) in [
        (off!(Selector, sport), sport),
        (off!(Selector, sport_mask), smask),
        (off!(Selector, dport), dport),
        (off!(Selector, dport_mask), dmask),
    ] {
        b[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    }
    put32(
        &mut b,
        off!(Selector, ifindex),
        crate::network::index(interface)?,
    );
    Ok(b)
}
fn selector_ts(b: &[u8], src: bool) -> io::Result<Ts> {
    if b.len() < size_of::<Selector>() {
        return Err(invalid());
    }
    let family = get16(b, off!(Selector, family));
    let proto = b[off!(Selector, proto)];
    let (addr, prefix, port_off, mask_off) = if src {
        (
            off!(Selector, saddr),
            off!(Selector, prefixlen_s),
            off!(Selector, sport),
            off!(Selector, sport_mask),
        )
    } else {
        (
            off!(Selector, daddr),
            off!(Selector, prefixlen_d),
            off!(Selector, dport),
            off!(Selector, dport_mask),
        )
    };
    let be = |o| u16::from_be_bytes(b[o..o + 2].try_into().unwrap());
    let (port, mask) = if [1, 58].contains(&proto) {
        (
            (be(off!(Selector, sport)) << 8) | be(off!(Selector, dport)),
            if be(off!(Selector, sport_mask)) | be(off!(Selector, dport_mask)) != 0 {
                65535
            } else {
                0
            },
        )
    } else {
        (be(port_off), be(mask_off))
    };
    let host = Host::from_kernel(family, &b[addr..addr + 16], 0)?;
    Ts::from_subnet(host, b[prefix], proto, port & mask, (port & mask) | !mask)
}
fn mark_attr(m: &mut Message, mark: Mark) -> io::Result<()> {
    if mark.mask != 0 {
        let mut b = [0; 8];
        put32(&mut b, 0, mark.value);
        put32(&mut b, 4, mark.mask);
        m.attr(MARK, &b)?;
    }
    Ok(())
}
fn id_attrs(m: &mut Message, mark: Mark, if_id: u32) -> io::Result<()> {
    mark_attr(m, mark)?;
    if if_id != 0 {
        m.attr32(IF_ID, if_id)?;
    }
    Ok(())
}
fn sa_id(id: &crate::model::SaId) -> Vec<u8> {
    let mut b = buffer::<crate::uapi::SaId>();
    id.dst.put(&mut b, off!(crate::uapi::SaId, daddr));
    b[off!(crate::uapi::SaId, spi)..off!(crate::uapi::SaId, spi) + 4]
        .copy_from_slice(&id.spi.to_be_bytes());
    put16(&mut b, off!(crate::uapi::SaId, family), id.dst.family());
    b[off!(crate::uapi::SaId, proto)] = id.proto;
    b
}
fn encap(src: &Host, dst: &Host) -> Vec<u8> {
    let mut b = buffer::<Encap>();
    put16(&mut b, off!(Encap, kind), 2);
    b[off!(Encap, sport)..off!(Encap, sport) + 2].copy_from_slice(&src.port.to_be_bytes());
    b[off!(Encap, dport)..off!(Encap, dport) + 2].copy_from_slice(&dst.port.to_be_bytes());
    b
}
fn algorithm(
    m: &mut Message,
    kind: u16,
    name: &str,
    key: &[u8],
    truncation: Option<u32>,
) -> io::Result<()> {
    if name.is_empty() || name.len() >= 64 || !name.is_ascii() {
        return Err(unsupported());
    }
    let mut b = Zeroizing::new(vec![0; if truncation.is_some() { 72 } else { 68 }]);
    b[..name.len()].copy_from_slice(name.as_bytes());
    put32(&mut b, 64, key.len() as u32 * 8);
    if let Some(t) = truncation {
        put32(&mut b, 68, t);
    }
    b.extend_from_slice(key);
    m.attr(kind, &b)
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
pub struct PolicyKey(pub Vec<u8>);
pub struct PolicyState {
    pub id: PolicyId,
    pub used_by: Vec<PolicyData>,
}
pub struct Xfrm {
    socket: Netlink,
    pub sas: HashSet<crate::model::SaId>,
    allocations: HashSet<(IpAddr, IpAddr, u32, u8)>,
    pub policies: HashMap<PolicyKey, PolicyState>,
    bypasses: Vec<(PolicyId, PolicyData)>,
    pub sa_dir: bool,
    pub lastused: bool,
}
impl Xfrm {
    pub fn new() -> io::Result<Self> {
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")?;
        let mut parts = release
            .trim()
            .split('.')
            .map(|s| s.parse::<u32>().unwrap_or(0));
        let version = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
        Ok(Self {
            socket: Netlink::new(NlFamily::Xfrm)?,
            sas: HashSet::new(),
            allocations: HashSet::new(),
            policies: HashMap::new(),
            bypasses: Vec::new(),
            sa_dir: version >= (6, 10),
            lastused: version >= (6, 2),
        })
    }
    pub fn features(&self) -> u32 {
        1 | 16 | 64 | if self.lastused { 32 } else { 0 }
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
        let mut b = buffer::<Spi>();
        src.put(&mut b, off!(Spi, info) + off!(Sa, saddr));
        dst.put(&mut b, off!(Spi, info) + off!(Sa, id) + off!(Id, daddr));
        b[off!(Sa, id) + off!(Id, proto)] = proto;
        b[off!(Sa, mode)] = 1;
        put16(&mut b, off!(Sa, family), src.family());
        put32(&mut b, off!(Spi, min), min);
        put32(&mut b, off!(Spi, max), max);
        let mut msg = Message::new(ALLOCSPI, NlmF::empty(), b);
        if self.sa_dir {
            msg.attr(SA_DIR, &[1])?;
        }
        for reply in self.socket.request(&msg)? {
            if reply.kind == NEWSA && reply.payload.len() >= size_of::<Sa>() {
                let o = off!(Sa, id) + off!(Id, spi);
                let spi = u32::from_be_bytes(reply.payload[o..o + 4].try_into().unwrap());
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
    fn sa_message(&self, id: &crate::model::SaId, data: &AddSa<'_>) -> io::Result<Message> {
        let mut b = buffer::<Sa>();
        id.src.put(&mut b, off!(Sa, saddr));
        id.dst.put(&mut b, off!(Sa, id) + off!(Id, daddr));
        let spi = off!(Sa, id) + off!(Id, spi);
        b[spi..spi + 4].copy_from_slice(&id.spi.to_be_bytes());
        b[off!(Sa, id) + off!(Id, proto)] = 50;
        put16(&mut b, off!(Sa, family), id.src.family());
        b[off!(Sa, mode)] = 1; // XFRM_MODE_TUNNEL, the only supported mode.
        put32(&mut b, off!(Sa, reqid), data.reqid);
        put32(&mut b, off!(Sa, seq), data.seq);
        // Tunnel SAs accept either inner address family.
        let mut flags = 32;
        if !data.copy_ecn {
            flags |= 1;
        }
        if data.inbound && [1, 2].contains(&data.copy_dscp) {
            flags |= 2;
        }
        if !data.inbound && !data.copy_df {
            flags |= 4;
        }
        if data.esn {
            flags |= 128;
        }
        b[off!(Sa, flags)] = flags;
        let limits = [
            nonzero(data.lifetime[3]),
            nonzero(data.lifetime[2]),
            nonzero(data.lifetime[5]),
            nonzero(data.lifetime[4]),
            data.lifetime[1],
            data.lifetime[0],
            0,
            0,
        ];
        for (i, limit) in limits.iter().enumerate() {
            put64(&mut b, off!(Sa, lft) + i * 8, *limit);
        }
        let replay = if data.inbound {
            data.replay_window
        } else {
            u32::from(data.esn && !self.sa_dir)
        };
        if !data.esn && replay <= 32 {
            b[off!(Sa, replay_window)] = replay as u8;
        }
        let mut m = Message::new(if data.update { UPDSA } else { NEWSA }, NlmF::ACK, b);
        if data.enc_alg != 1024 {
            let (name, icv) = enc_algorithm(data.enc_alg)
                .or_else(|| (!data.enc_name.is_empty()).then_some((data.enc_name.as_str(), None)))
                .ok_or_else(unsupported)?;
            algorithm(
                &mut m,
                if icv.is_some() { AEAD } else { CRYPT },
                name,
                data.enc_key,
                icv,
            )?;
        }
        if data.int_alg != 1024 {
            let (name, trunc) = int_algorithm(data.int_alg)
                .or_else(|| (!data.int_name.is_empty()).then_some((data.int_name.as_str(), None)))
                .ok_or_else(unsupported)?;
            algorithm(
                &mut m,
                if trunc.is_some() { AUTH_TRUNC } else { AUTH },
                name,
                data.int_key,
                trunc,
            )?;
        }
        if data.encap {
            m.attr(ENCAP, &encap(&id.src, &id.dst))?;
        }
        if data.mark.value | data.mark.mask != 0 {
            m.attr32(29, data.mark.value)?;
            m.attr32(30, data.mark.mask)?;
        }
        if data.tfc != 0 {
            m.attr32(22, data.tfc)?;
        }
        if data.esn || replay > 32 {
            let words = (replay as usize).div_ceil(32);
            let mut state = vec![0; 24 + words * 4];
            put32(&mut state, 0, words as u32);
            put32(&mut state, 20, replay);
            m.attr(REPLAY_ESN, &state)?;
        }
        if !data.inbound && [1, 3].contains(&data.copy_dscp) {
            m.attr32(24, 1)?;
        }
        id_attrs(&mut m, id.mark, id.if_id)?;
        if self.sa_dir {
            m.attr(SA_DIR, &[if data.inbound { 1 } else { 2 }])?;
        }
        Ok(m)
    }

    pub fn add_sa(&mut self, id: &crate::model::SaId, data: &AddSa<'_>) -> io::Result<()> {
        if id.proto != 50 || id.if_id == 0 {
            return Err(unsupported());
        }
        if data.update && !self.owned(id) {
            return Err(missing());
        }
        let mut msg = self.sa_message(id, data)?;
        let mut result = self.socket.ack(&msg);
        if matches!(
            result.as_ref().err().and_then(io::Error::raw_os_error),
            Some(libc::ENOENT | libc::ESRCH)
        ) && data.update
        {
            msg.kind = NEWSA;
            result = self.socket.ack(&msg);
        }
        result?;
        self.sas.insert(id.key());
        self.allocations
            .remove(&(id.src.ip, id.dst.ip, id.spi, id.proto));
        Ok(())
    }
    fn read_sa(&mut self, id: &crate::model::SaId) -> io::Result<Reply> {
        if !self.owned(id) {
            return Err(missing());
        }
        let mut m = Message::new(GETSA, NlmF::empty(), sa_id(id));
        id_attrs(&mut m, id.mark, id.if_id)?;
        self.socket
            .request(&m)?
            .into_iter()
            .find(|r| r.kind == NEWSA && r.payload.len() >= size_of::<Sa>())
            .ok_or_else(missing)
    }
    pub fn query_sa(&mut self, id: &crate::model::SaId) -> io::Result<(u64, u64, u64)> {
        let r = self.read_sa(id)?;
        let o = off!(Sa, curlft);
        let mut last = 0;
        for (kind, b) in netlink::attrs(&r.payload[netlink::align(size_of::<Sa>())..])?.iter() {
            if kind == LASTUSED && b.len() == 8 {
                last = get64(b, 0);
            }
        }
        Ok((
            get64(&r.payload, o + off!(LifetimeCur, bytes)),
            get64(&r.payload, o + off!(LifetimeCur, packets)),
            last,
        ))
    }
    fn delete_one(&mut self, id: &crate::model::SaId) -> io::Result<()> {
        if !self.owned(id) {
            return Err(missing());
        }
        let mut m = Message::new(DELSA, NlmF::ACK, sa_id(id));
        id_attrs(&mut m, id.mark, id.if_id)?;
        match self.socket.ack(&m) {
            Ok(()) => (),
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => (),
            Err(e) => return Err(e),
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

impl Xfrm {
    pub fn policy_key(id: &PolicyId) -> io::Result<PolicyKey> {
        let mut b = selector(&id.src, &id.dst, "")?;
        b.push(id.dir);
        b.extend_from_slice(&(id.mark.value & id.mark.mask).to_be_bytes());
        b.extend_from_slice(&id.mark.mask.to_be_bytes());
        b.extend_from_slice(&id.if_id.to_be_bytes());
        Ok(PolicyKey(b))
    }
    fn priorities(id: &PolicyId, data: &PolicyData) -> (u32, u32) {
        let (_, sp) = id.src.subnet();
        let (_, dp) = id.dst.subnet();
        let (_, sm) = id.src.ports();
        let (_, dm) = id.dst.ports();
        let base = match data.prio {
            0 => 200000,
            3 => 600000,
            _ => 400000,
        };
        let auto = base
            - (sp as u32 + dp as u32) * 512
            - if id.src.proto | id.dst.proto != 0 {
                256
            } else {
                0
            }
            - (sm.count_ones() + dm.count_ones()) * 4
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
    fn policy_message(id: &PolicyId, data: &PolicyData, update: bool) -> io::Result<Message> {
        let mut b = buffer::<Policy>();
        let sel = selector(&id.src, &id.dst, "")?;
        b[..sel.len()].copy_from_slice(&sel);
        for i in 0..4 {
            put64(&mut b, off!(Policy, lft) + i * 8, u64::MAX);
        }
        put32(&mut b, off!(Policy, priority), Self::priorities(id, data).0);
        b[off!(Policy, dir)] = id.dir;
        b[off!(Policy, action)] = u8::from(data.kind == 3);
        let mut m = Message::new(if update { UPDPOLICY } else { NEWPOLICY }, NlmF::ACK, b);
        if data.kind == 1 && data.reqid != 0 {
            let mut t = buffer::<Template>();
            t[off!(Template, id) + off!(Id, proto)] = 50;
            if id.dir == 1 {
                t[off!(Id, spi)..off!(Id, spi) + 4]
                    .copy_from_slice(&data.esp.unwrap_or(0).to_be_bytes());
            }
            put16(&mut t, off!(Template, family), data.src.family());
            put32(&mut t, off!(Template, reqid), data.reqid);
            t[off!(Template, mode)] = 1;
            for o in [
                off!(Template, aalgos),
                off!(Template, ealgos),
                off!(Template, calgos),
            ] {
                put32(&mut t, o, u32::MAX);
            }
            data.src.put(&mut t, off!(Template, saddr));
            data.dst.put(&mut t, off!(Template, id) + off!(Id, daddr));
            m.attr(TMPL, &t)?;
        }
        id_attrs(&mut m, id.mark, id.if_id)?;
        Ok(m)
    }
    pub fn add_policy(&mut self, id: PolicyId, data: PolicyData) -> io::Result<()> {
        let key = Self::policy_key(&id)?;
        let current = self.policies.get(&key);
        let mut uses = current.map(|p| p.used_by.clone()).unwrap_or_default();
        let priority = Self::priorities(&id, &data);
        let pos = uses
            .iter()
            .position(|p| {
                let existing = Self::priorities(&id, p);
                existing > priority || (existing == priority && (p.reqid == 0 || data.reqid != 0))
            })
            .unwrap_or(uses.len());
        if pos == 0 {
            self.socket
                .ack(&Self::policy_message(&id, &data, current.is_some())?)?;
        }
        uses.insert(pos, data);
        self.policies.insert(key, PolicyState { id, used_by: uses });
        Ok(())
    }
    fn delete_policy_message(id: &PolicyId) -> io::Result<Message> {
        let mut b = buffer::<crate::uapi::PolicyId>();
        let sel = selector(&id.src, &id.dst, "")?;
        b[..sel.len()].copy_from_slice(&sel);
        b[off!(crate::uapi::PolicyId, dir)] = id.dir;
        let mut m = Message::new(DELPOLICY, NlmF::ACK, b);
        id_attrs(&mut m, id.mark, id.if_id)?;
        Ok(m)
    }
    pub fn delete_policy(&mut self, id: &PolicyId, data: &PolicyData) -> io::Result<()> {
        let key = Self::policy_key(id)?;
        let state = self.policies.get(&key).ok_or_else(missing)?;
        let mut uses = state.used_by.clone();
        let pos = uses.iter().position(|p| p == data).ok_or_else(missing)?;
        uses.remove(pos);
        if uses.is_empty() {
            match self.socket.ack(&Self::delete_policy_message(&state.id)?) {
                Ok(()) => (),
                Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => (),
                Err(e) => return Err(e),
            }
            self.policies.remove(&key);
        } else {
            if pos == 0 {
                self.socket
                    .ack(&Self::policy_message(&state.id, &uses[0], true)?)?;
            }
            self.policies.get_mut(&key).unwrap().used_by = uses;
        }
        Ok(())
    }
    pub fn query_policy(&mut self, id: &PolicyId) -> io::Result<u64> {
        if !self.policies.contains_key(&Self::policy_key(id)?) {
            return Err(missing());
        }
        let mut m = Self::delete_policy_message(id)?;
        m.kind = GETPOLICY;
        m.flags = NlmF::empty();
        let r = self
            .socket
            .request(&m)?
            .into_iter()
            .find(|r| r.kind == NEWPOLICY && r.payload.len() >= size_of::<Policy>())
            .ok_or_else(missing)?;
        let time = get64(
            &r.payload,
            off!(Policy, curlft) + off!(LifetimeCur, use_time),
        );
        if time == 0 {
            return Ok(0);
        }
        let monotonic = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| invalid())?
            .as_secs();
        Ok((monotonic.tv_sec as u64).saturating_sub(wall.saturating_sub(time)))
    }
    pub fn flush_policies(&mut self) -> io::Result<()> {
        let keys: Vec<_> = self
            .policies
            .iter()
            .filter(|(_, p)| p.id.if_id != 0)
            .map(|(k, _)| k.clone())
            .collect();
        for key in keys {
            let state = &self.policies[&key];
            self.socket.ack(&Self::delete_policy_message(&state.id)?)?;
            self.policies.remove(&key);
        }
        Ok(())
    }
    pub fn port_bypass(&mut self, family: u16, port: u16) -> io::Result<()> {
        if port == 0 {
            return Err(invalid());
        }
        let any = Host::any(family)?;
        for dir in [1, 0] {
            let wildcard = Ts::from_subnet(any.clone(), 0, 17, 0, 65535)?;
            let specific = Ts::from_subnet(any.clone(), 0, 17, port, port)?;
            let (src, dst) = if dir == 1 {
                (specific, wildcard)
            } else {
                (wildcard, specific)
            };
            let id = PolicyId {
                dir,
                src,
                dst,
                mark: Mark::default(),
                if_id: 0,
            };
            if self.bypasses.iter().any(|(p, _)| p == &id) {
                continue;
            }
            let data = PolicyData {
                kind: 2,
                prio: 0,
                manual_prio: 32,
                src: any.clone(),
                dst: any.clone(),
                reqid: 0,
                policy_count: 1,
                esp: None,
            };
            self.add_policy(id.clone(), data.clone())?;
            self.bypasses.push((id, data));
        }
        Ok(())
    }
    pub fn remove_bypasses(&mut self) -> io::Result<()> {
        while let Some((id, data)) = self.bypasses.last().cloned() {
            self.delete_policy(&id, &data)?;
            self.bypasses.pop();
        }
        Ok(())
    }
    pub fn has_tunnel_policies(&self) -> bool {
        self.policies.values().any(|p| p.id.if_id != 0)
    }
    pub fn event(&mut self, m: &Reply) -> io::Result<Option<rpc::Event>> {
        let b = &m.payload;
        let mut event = rpc::Event {
            kind: rpc::Event_kind::ready,
            expiry: None,
            acquire: None,
            mapping: None,
            addressChanged: None,
        };
        match m.kind {
            23 => {
                if b.len() < size_of::<Acquire>() {
                    return Err(invalid());
                }
                let mut reqid = 0;
                let mut if_id = 0;
                for (kind, a) in netlink::attrs(&b[netlink::align(size_of::<Acquire>())..])?.iter()
                {
                    if kind == TMPL && a.len() >= size_of::<Template>() {
                        reqid = get32(a, off!(Template, reqid));
                    }
                    if kind == IF_ID && a.len() == 4 {
                        if_id = get32(a, 0);
                    }
                }
                if !self
                    .policies
                    .values()
                    .any(|p| p.id.if_id == if_id && p.used_by.iter().any(|d| d.reqid == reqid))
                {
                    return Ok(None);
                }
                let sel = &b[off!(Acquire, sel)..off!(Acquire, sel) + size_of::<Selector>()];
                event.kind = rpc::Event_kind::acquire;
                event.acquire = Some(rpc::Acquire {
                    reqid: reqid.into(),
                    src: rpc_selector(selector_ts(sel, true)?),
                    dst: rpc_selector(selector_ts(sel, false)?),
                    sequence: get32(b, off!(Acquire, seq)).into(),
                });
            }
            24 => {
                if b.len() < size_of::<Expire>() {
                    return Err(invalid());
                }
                let proto = b[off!(Sa, id) + off!(Id, proto)];
                let o = off!(Sa, id) + off!(Id, spi);
                let spi = u32::from_be_bytes(b[o..o + 4].try_into().unwrap());
                let family = get16(b, off!(Sa, family));
                let dst = Host::from_kernel(family, &b[off!(Sa, id) + off!(Id, daddr)..], 0)?;
                let src = Host::from_kernel(family, &b[off!(Sa, saddr)..], 0)?;
                let mut mark = Mark::default();
                let mut if_id = 0;
                for (kind, a) in netlink::attrs(&b[netlink::align(size_of::<Expire>())..])?.iter() {
                    if kind == IF_ID && a.len() == 4 {
                        if_id = get32(a, 0);
                    }
                    if kind == MARK && a.len() == 8 {
                        mark = Mark {
                            value: get32(a, 0),
                            mask: get32(a, 4),
                        };
                    }
                }
                let id = crate::model::SaId {
                    src,
                    dst: dst.clone(),
                    spi,
                    proto,
                    mark,
                    if_id,
                }
                .key();
                if !self.sas.contains(&id) {
                    return Ok(None);
                }
                let hard = b[off!(Expire, hard)] != 0;
                if hard {
                    self.sas.remove(&id);
                }
                event.kind = rpc::Event_kind::expire;
                event.expiry = Some(rpc::Expiry {
                    protocol: proto.into(),
                    spi: spi.into(),
                    destination: endpoint(dst),
                    hard,
                });
            }
            38 => {
                if b.len() < size_of::<Mapping>() {
                    return Err(invalid());
                }
                let spi = u32::from_be_bytes(b[16..20].try_into().unwrap());
                let family = get16(b, off!(crate::uapi::SaId, family));
                let dst = Host::from_kernel(family, b, 0)?;
                if b[off!(crate::uapi::SaId, proto)] != 50
                    || !self
                        .sas
                        .iter()
                        .any(|id| id.dst.ip == dst.ip && id.spi == spi && id.proto == 50)
                {
                    return Ok(None);
                }
                let o = off!(Mapping, new_sport);
                let remote = Host::from_kernel(
                    family,
                    &b[off!(Mapping, new_saddr)..],
                    u16::from_be_bytes(b[o..o + 2].try_into().unwrap()),
                )?;
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
    fn linux_uapi_layout_and_icmp_selectors() {
        assert_eq!(size_of::<Sa>(), 224);
        assert_eq!(size_of::<Policy>(), 168);
        assert_eq!(size_of::<Selector>(), 56);
        assert_eq!(size_of::<Template>(), 64);
        let host = Host {
            ip: "10.1.0.0".parse().unwrap(),
            port: 0,
        };
        let src = Ts::from_subnet(host.clone(), 24, 1, 0x0800, 0x0800).unwrap();
        let dst = Ts::from_subnet(host, 24, 0, 0, 65535).unwrap();
        let sel = selector(&src, &dst, "").unwrap();
        let ts = selector_ts(&sel, true).unwrap();
        assert_eq!(ts.from_port, 0x0800);
    }
}
