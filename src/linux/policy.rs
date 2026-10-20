// SPDX-License-Identifier: GPL-2.0-or-later
// Policy semantics ported from kernel_netlink_ipsec.c (Martin Willi,
// Tobias Brunner and contributors; Copyright secunet Security Networks AG).
// Packet layouts and serialization are supplied by netlink-packet-xfrm.
use super::{
    netlink::{Message, Netlink, NlFamily, NlmF},
    xfrm::{host, id_attrs, message, missing, monotonic_use_time},
};
use crate::{
    error::invalid,
    model::*,
    policy::{PolicyKernel, PolicyStatus},
};
use ipnet::IpNet;
use netlink_packet_core::{Nla, Parseable};
use netlink_packet_xfrm::{self as packet, XfrmAttrs as Attr, XfrmMessage};
use std::{collections::HashMap, io};

fn selector(src: &Ts, dst: &Ts, interface: &str) -> io::Result<packet::Selector> {
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
        ifindex: super::network::index(interface)? as i32,
        user: 0,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::xfrm::selector_ts;
    use netlink_packet_core::Emitable;
    use std::collections::HashSet;

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
