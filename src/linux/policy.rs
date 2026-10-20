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
    model::{Host, Mark},
    policy::{ObservedPolicy, PolicyConfig, PolicyKernel, PolicyKey, PolicySpec, PolicyTemplate},
};
use ipnet::IpNet;
use netlink_packet_core::{Nla, Parseable};
use netlink_packet_xfrm::{self as packet, XfrmAttrs as Attr, XfrmMessage};
use std::io;

fn selector(id: &PolicyKey) -> packet::Selector {
    packet::Selector {
        saddr: packet::Address::from_ip(&id.src.addr()),
        daddr: packet::Address::from_ip(&id.dst.addr()),
        family: Host {
            ip: id.src.addr(),
            port: 0,
        }
        .family(),
        prefixlen_s: id.src.prefix_len(),
        prefixlen_d: id.dst.prefix_len(),
        proto: id.protocol,
        sport: id.src_port,
        sport_mask: id.src_port_mask,
        dport: id.dst_port,
        dport_mask: id.dst_port_mask,
        ifindex: 0,
        user: 0,
    }
}

/// Policies are identified by selectors/direction/mark/interface ID, as before.
/// Kernel-assigned policy indices are not ownership or configuration fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyHandle(PolicyKey);

pub struct LinuxPolicies {
    socket: Netlink,
}
impl LinuxPolicies {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            socket: Netlink::new(NlFamily::Xfrm)?,
        })
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
    fn policy_spec(spec: &PolicySpec) -> packet::policy::ModifyMessage {
        let info = packet::UserPolicyInfo {
            selector: selector(&spec.id),
            priority: spec.config.priority,
            direction: spec.id.dir,
            action: u8::from(spec.config.block),
            ..Default::default()
        };
        let mut nlas = Vec::new();
        if let Some(template) = &spec.config.template {
            nlas.push(Attr::Template(vec![packet::UserTemplate {
                id: packet::Id {
                    daddr: packet::Address::from_ip(&template.dst),
                    spi: template.spi,
                    proto: 50,
                },
                saddr: packet::Address::from_ip(&template.src),
                family: Host {
                    ip: template.src,
                    port: 0,
                }
                .family(),
                reqid: template.reqid,
                mode: packet::XFRM_MODE_TUNNEL,
                share: 0,
                optional: 0,
                aalgos: u32::MAX,
                ealgos: u32::MAX,
                calgos: u32::MAX,
            }]));
        }
        nlas.extend(id_attrs(spec.id.mark, spec.id.if_id));
        packet::policy::ModifyMessage {
            user_policy_info: info,
            nlas,
        }
    }
    fn policy_message(spec: &PolicySpec, update: bool) -> Message {
        let request = Self::policy_spec(spec);
        let request = if update {
            XfrmMessage::UpdatePolicy(request)
        } else {
            XfrmMessage::AddPolicy(request)
        };
        message(NlmF::ACK, &request)
    }
    fn policy_id(id: &PolicyKey) -> packet::policy::DelGetMessage {
        packet::policy::DelGetMessage {
            user_policy_id: packet::UserPolicyId {
                selector: selector(id),
                direction: id.dir,
                ..Default::default()
            },
            nlas: id_attrs(id.mark, id.if_id),
        }
    }

    fn configuration(
        id: &PolicyKey,
        policy: &packet::policy::ModifyMessage,
    ) -> Option<PolicyConfig> {
        let block = match policy.user_policy_info.action {
            0 => false,
            1 => true,
            _ => return None,
        };
        let templates = policy.nlas.iter().find_map(|attr| match attr {
            Attr::Template(templates) => Some(templates.as_slice()),
            _ => None,
        });
        let template = match templates {
            None | Some([]) => None,
            Some([template]) => Some(PolicyTemplate {
                src: host(template.family, template.saddr, 0).ok()?.ip,
                dst: host(template.family, template.id.daddr, 0).ok()?.ip,
                reqid: template.reqid,
                spi: template.id.spi,
            }),
            _ => return None,
        };
        let config = PolicyConfig {
            priority: policy.user_policy_info.priority,
            block,
            template,
        };
        let encoded = Self::policy_spec(&PolicySpec {
            id: id.clone(),
            config: config.clone(),
        });
        // Validate that decoding is lossless for configuration. Unsupported
        // flags, limits, templates or attributes cannot silently look matching.
        // This compares the observed record with its own encoding, never with
        // desired state; repair decisions belong to the shared controller.
        (Self::policy_configuration(policy.clone()) == Self::policy_configuration(encoded))
            .then_some(config)
    }
    fn observed(policy: packet::policy::ModifyMessage) -> io::Result<ObservedPolicy<PolicyHandle>> {
        let info = &policy.user_policy_info;
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
        let id = Self::selector_key(&info.selector, info.direction, mark, if_id)?;
        Ok(ObservedPolicy {
            handle: PolicyHandle(id.clone()),
            config: Self::configuration(&id, &policy),
            id,
            last_use: monotonic_use_time(info.lifetime_cur.use_time)?,
        })
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
    type Handle = PolicyHandle;

    fn list(&mut self) -> io::Result<Vec<ObservedPolicy<PolicyHandle>>> {
        let request = XfrmMessage::GetPolicy(packet::policy::DelGetMessage::default());
        let mut observed = Vec::new();
        for reply in self.socket.request(&message(NlmF::DUMP, &request))? {
            if reply.kind != packet::XFRM_MSG_NEWPOLICY {
                continue;
            }
            let policy = packet::policy::ModifyMessage::parse(reply.payload.as_slice())
                .map_err(io::Error::other)?;
            let info = &policy.user_policy_info;
            // Other interface/user selectors, security labels and policy
            // tables are separate scopes; our CRUD API addresses main policies.
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
            observed.push(Self::observed(policy)?);
        }
        Ok(observed)
    }
    fn get(&mut self, handle: &PolicyHandle) -> io::Result<ObservedPolicy<PolicyHandle>> {
        let request = XfrmMessage::GetPolicy(Self::policy_id(&handle.0));
        let reply = self
            .socket
            .request(&message(NlmF::empty(), &request))?
            .into_iter()
            .find(|reply| reply.kind == packet::XFRM_MSG_NEWPOLICY)
            .ok_or_else(missing)?;
        let policy = packet::policy::ModifyMessage::parse(reply.payload.as_slice())
            .map_err(io::Error::other)?;
        Self::observed(policy)
    }
    fn create(&mut self, spec: &PolicySpec) -> io::Result<PolicyHandle> {
        self.socket.ack(&Self::policy_message(spec, false))?;
        Ok(PolicyHandle(spec.id.clone()))
    }
    fn update(&mut self, handle: &PolicyHandle, spec: &PolicySpec) -> io::Result<()> {
        if handle.0 != spec.id {
            return Err(invalid());
        }
        self.socket.ack(&Self::policy_message(spec, true))
    }
    fn delete(&mut self, handle: &PolicyHandle) -> io::Result<()> {
        let request = XfrmMessage::DeletePolicy(Self::policy_id(&handle.0));
        match self.socket.ack(&message(NlmF::ACK, &request)) {
            Ok(()) => Ok(()),
            Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::xfrm::selector_ts;
    use crate::model::{PolicyData, PolicyId, Ts};
    use netlink_packet_core::Emitable;
    use std::collections::HashSet;

    #[test]
    fn observations_ignore_usage_metadata_but_preserve_configuration_changes() {
        for (src, dst, prefix) in [
            ("192.0.2.1", "192.0.2.2", 32),
            ("2001:db8::1", "2001:db8::2", 128),
        ] {
            let src = Host {
                ip: src.parse().unwrap(),
                port: 0,
            };
            let dst = Host {
                ip: dst.parse().unwrap(),
                port: 0,
            };
            let id = PolicyKey::new(&PolicyId {
                src: Ts::from_subnet(src.clone(), prefix, 0, 0, u16::MAX).unwrap(),
                dst: Ts::from_subnet(dst.clone(), prefix, 0, 0, u16::MAX).unwrap(),
                dir: 1,
                mark: Mark::default(),
                if_id: 41,
            })
            .unwrap();
            let config = PolicyConfig {
                priority: 100,
                block: false,
                template: Some(PolicyTemplate {
                    src: src.ip,
                    dst: dst.ip,
                    reqid: 42,
                    spi: 0x10203,
                }),
            };
            let mut native = LinuxPolicies::policy_spec(&PolicySpec {
                id: id.clone(),
                config: config.clone(),
            });
            native.user_policy_info.index = 123;
            native.user_policy_info.lifetime_cur.add_time = 1234;
            native.user_policy_info.lifetime_cur.bytes = 5678;
            native.nlas.push(Attr::PolicyType(packet::UserPolicyType {
                ptype: 0,
                reserved1: 0,
                reserved2: 0,
            }));
            native.nlas.reverse();
            assert_eq!(LinuxPolicies::configuration(&id, &native), Some(config));
            native.user_policy_info.flags = 1;
            assert_eq!(LinuxPolicies::configuration(&id, &native), None);
            native.user_policy_info.flags = 0;
            for attr in &mut native.nlas {
                if let Attr::Template(templates) = attr {
                    templates[0].mode = packet::XFRM_MODE_TRANSPORT;
                }
            }
            assert_eq!(LinuxPolicies::configuration(&id, &native), None);
        }
    }

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
                let spec = PolicySpec::new(id, &data).unwrap();
                let request = LinuxPolicies::policy_message(&spec, false);
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
            let keys = HashSet::from([PolicyKey::new(&id).unwrap()]);
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
            assert!(keys.contains(&PolicyKey::new(&equivalent).unwrap()));

            let mut different = id.clone();
            different.src.to_port = 4095;
            assert!(!keys.contains(&PolicyKey::new(&different).unwrap()));
            different = id.clone();
            different.dir = 2;
            assert!(!keys.contains(&PolicyKey::new(&different).unwrap()));
            different = id.clone();
            different.if_id += 1;
            assert!(!keys.contains(&PolicyKey::new(&different).unwrap()));
            different = id.clone();
            different.mark.mask = 0xffff;
            assert!(!keys.contains(&PolicyKey::new(&different).unwrap()));
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
            let selector = selector(
                &PolicyKey::new(&PolicyId {
                    src: src.clone(),
                    dst: dst.clone(),
                    dir: 1,
                    mark: Mark::default(),
                    if_id: 41,
                })
                .unwrap(),
            );
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
            let keys = HashSet::from([PolicyKey::new(&id).unwrap()]);
            // strongSwan may put the same ICMP type/code on either selector.
            std::mem::swap(&mut id.src, &mut id.dst);
            assert!(keys.contains(&PolicyKey::new(&id).unwrap()));
            id.dst.from_port += 1;
            id.dst.to_port += 1;
            assert!(!keys.contains(&PolicyKey::new(&id).unwrap()));
        }
    }
}
