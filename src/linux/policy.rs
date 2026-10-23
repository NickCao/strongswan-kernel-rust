// SPDX-License-Identifier: GPL-2.0-or-later
// Policy semantics ported from kernel_netlink_ipsec.c (Martin Willi,
// Tobias Brunner and contributors; Copyright secunet Security Networks AG).
// Packet layouts and serialization are supplied by netlink-packet-xfrm.
use super::{
    iptfs,
    netlink::{Message, Netlink, NlFamily, NlmF},
    xfrm::{host, id_attrs, message, missing, monotonic_use_time},
};
use crate::{
    error::invalid,
    model::{Endpoint, Mark, PolicyDirection},
    policy::{ObservedPolicy, PolicyConfig, PolicyKernel, PolicyKey, PolicySpec, PolicyTemplate},
};
use ipnet::IpNet;
use netlink_packet_core::{Nla, Parseable};
use netlink_packet_xfrm::{self as packet, XfrmAttrs as Attr, XfrmMessage};
use rustix::net::ipproto;
use std::io;

fn selector(id: &PolicyKey) -> packet::Selector {
    packet::Selector {
        saddr: packet::Address::from_ip(&id.src.addr()),
        daddr: packet::Address::from_ip(&id.dst.addr()),
        family: Endpoint::new(id.src.addr(), 0).family(),
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

/// The kernel index is the native key, never an ownership marker. XFRM also
/// requires mark, interface ID and type qualifiers for index lookups.
#[derive(Clone, Debug)]
pub struct PolicyHandle {
    index: u32,
    id: Option<PolicyKey>,
    mark: Mark,
    if_id: u32,
    policy_type: u8,
}
impl crate::policy::PolicyHandle for PolicyHandle {
    fn id(&self) -> Option<&PolicyKey> {
        self.id.as_ref()
    }
}
impl PolicyHandle {
    fn request(&self) -> packet::policy::DelGetMessage {
        let mut nlas = id_attrs(self.mark, self.if_id);
        if self.policy_type != packet::XFRM_POLICY_TYPE_MAIN {
            nlas.push(Attr::PolicyType(packet::UserPolicyType {
                ptype: self.policy_type,
                ..Default::default()
            }));
        }
        packet::policy::DelGetMessage {
            user_policy_id: packet::UserPolicyId {
                index: self.index,
                // The bottom three index bits encode the native direction.
                direction: (self.index & 7) as u8,
                ..Default::default()
            },
            nlas,
        }
    }
}

pub struct LinuxPolicies {
    socket: Netlink,
}
impl LinuxPolicies {
    pub async fn new() -> io::Result<Self> {
        Ok(Self {
            socket: Netlink::new(NlFamily::Xfrm).await?,
        })
    }
    fn selector_key(
        sel: &packet::Selector,
        dir: u8,
        mark: Mark,
        if_id: u32,
    ) -> io::Result<PolicyKey> {
        Ok(PolicyKey {
            src: IpNet::new(host(sel.family, sel.saddr, 0)?.address, sel.prefixlen_s)
                .map_err(|_| invalid())?,
            dst: IpNet::new(host(sel.family, sel.daddr, 0)?.address, sel.prefixlen_d)
                .map_err(|_| invalid())?,
            src_port: sel.sport,
            src_port_mask: sel.sport_mask,
            dst_port: sel.dport,
            dst_port_mask: sel.dport_mask,
            protocol: sel.proto,
            dir: PolicyDirection::from(u32::from(dir)),
            mark: Mark {
                value: mark.value & mark.mask,
                mask: mark.mask,
            },
            if_id,
        })
    }
    fn policy_spec(spec: &PolicySpec) -> io::Result<packet::policy::ModifyMessage> {
        let info = packet::UserPolicyInfo {
            selector: selector(&spec.id),
            priority: spec.config.priority,
            direction: u32::from(spec.id.dir).try_into().map_err(|_| invalid())?,
            action: if spec.config.block {
                packet::XFRM_POLICY_BLOCK
            } else {
                packet::XFRM_POLICY_ALLOW
            },
            flags: if spec.config.forward_icmp {
                packet::XFRM_POLICY_ICMP
            } else {
                0
            },
            ..Default::default()
        };
        let mut nlas = Vec::new();
        if let Some(template) = &spec.config.template {
            nlas.push(Attr::Template(vec![packet::UserTemplate {
                id: packet::Id {
                    daddr: packet::Address::from_ip(&template.dst),
                    spi: template.spi,
                    proto: ipproto::ESP.as_raw().get() as u8,
                },
                saddr: packet::Address::from_ip(&template.src),
                family: Endpoint::new(template.src, 0).family(),
                reqid: template.reqid,
                mode: iptfs::mode(template.mode)?,
                share: packet::XFRM_SHARE_ANY,
                optional: 0,
                aalgos: u32::MAX,
                ealgos: u32::MAX,
                calgos: u32::MAX,
            }]));
        }
        nlas.extend(id_attrs(spec.id.mark, spec.id.if_id));
        Ok(packet::policy::ModifyMessage {
            user_policy_info: info,
            nlas,
        })
    }
    fn policy_message(spec: &PolicySpec, update: bool) -> io::Result<Message> {
        let request = Self::policy_spec(spec)?;
        let request = if update {
            XfrmMessage::UpdatePolicy(request)
        } else {
            XfrmMessage::AddPolicy(request)
        };
        Ok(message(NlmF::ACK, &request))
    }
    fn policy_id(id: &PolicyKey) -> io::Result<packet::policy::DelGetMessage> {
        Ok(packet::policy::DelGetMessage {
            user_policy_id: packet::UserPolicyId {
                selector: selector(id),
                direction: u32::from(id.dir).try_into().map_err(|_| invalid())?,
                ..Default::default()
            },
            nlas: id_attrs(id.mark, id.if_id),
        })
    }
    async fn read(
        &mut self,
        request: packet::policy::DelGetMessage,
    ) -> io::Result<ObservedPolicy<PolicyHandle>> {
        let reply = self
            .socket
            .request(&message(NlmF::empty(), &XfrmMessage::GetPolicy(request)))
            .await?
            .into_iter()
            .find(|reply| reply.kind == packet::XFRM_MSG_NEWPOLICY)
            .ok_or_else(missing)?;
        let policy = packet::policy::ModifyMessage::parse(reply.payload.as_slice())
            .map_err(io::Error::other)?;
        Self::observed(policy)
    }

    fn configuration(
        id: &PolicyKey,
        policy: &packet::policy::ModifyMessage,
    ) -> Option<PolicyConfig> {
        let block = match policy.user_policy_info.action {
            packet::XFRM_POLICY_ALLOW => false,
            packet::XFRM_POLICY_BLOCK => true,
            _ => return None,
        };
        let templates = policy.nlas.iter().find_map(|attr| match attr {
            Attr::Template(templates) => Some(templates.as_slice()),
            _ => None,
        });
        let template = match templates {
            None | Some([]) => None,
            Some([template]) => Some(PolicyTemplate {
                mode: iptfs::observed_mode(template.mode)?,
                src: host(template.family, template.saddr, 0).ok()?.address,
                dst: host(template.family, template.id.daddr, 0).ok()?.address,
                reqid: template.reqid,
                spi: template.id.spi,
            }),
            _ => return None,
        };
        let config = PolicyConfig {
            priority: policy.user_policy_info.priority,
            block,
            forward_icmp: policy.user_policy_info.flags & packet::XFRM_POLICY_ICMP != 0,
            template,
        };
        let encoded = Self::policy_spec(&PolicySpec {
            id: id.clone(),
            config: config.clone(),
        })
        .ok()?;
        // Validate that decoding is lossless for configuration. Unsupported
        // flags, limits, templates or attributes cannot silently look matching.
        // This compares the observed record with its own encoding, never with
        // desired state; repair decisions belong to the shared controller.
        (Self::policy_configuration(policy.clone()) == Self::policy_configuration(encoded))
            .then_some(config)
    }
    fn observed(policy: packet::policy::ModifyMessage) -> io::Result<ObservedPolicy<PolicyHandle>> {
        let info = &policy.user_policy_info;
        let (mut mark, mut if_id, mut policy_type) =
            (Mark::default(), 0, packet::XFRM_POLICY_TYPE_MAIN);
        for attr in &policy.nlas {
            match attr {
                Attr::Mark(value) => {
                    mark = Mark {
                        value: value.value,
                        mask: value.mask,
                    }
                }
                Attr::IfId(value) => if_id = *value,
                Attr::PolicyType(value) => policy_type = value.ptype,
                _ => (),
            }
        }
        let representable = info.selector.ifindex == 0
            && info.selector.user == 0
            && policy_type == packet::XFRM_POLICY_TYPE_MAIN
            && !policy
                .nlas
                .iter()
                .any(|attr| matches!(attr, Attr::SecurityContext(_)));
        let id = representable
            .then(|| Self::selector_key(&info.selector, info.direction, mark, if_id).ok())
            .flatten();
        let config = id.as_ref().and_then(|id| Self::configuration(id, &policy));
        Ok(ObservedPolicy {
            handle: PolicyHandle {
                index: info.index,
                id,
                mark,
                if_id,
                policy_type,
            },
            config,
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
            Attr::PolicyType(value) => value.ptype != packet::XFRM_POLICY_TYPE_MAIN,
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

    async fn list(&mut self) -> io::Result<Vec<ObservedPolicy<PolicyHandle>>> {
        let request = XfrmMessage::GetPolicy(packet::policy::DelGetMessage::default());
        let mut observed = Vec::new();
        for reply in self.socket.request(&message(NlmF::DUMP, &request)).await? {
            if reply.kind != packet::XFRM_MSG_NEWPOLICY {
                continue;
            }
            let policy = packet::policy::ModifyMessage::parse(reply.payload.as_slice())
                .map_err(io::Error::other)?;
            // Per-socket policies belong to the socket and cannot be managed
            // through global CRUD. Their directions are offset beyond 0..=2.
            if policy.user_policy_info.direction > packet::XFRM_POLICY_FWD {
                continue;
            }
            observed.push(Self::observed(policy)?);
        }
        Ok(observed)
    }
    async fn get(&mut self, id: &PolicyKey) -> io::Result<ObservedPolicy<PolicyHandle>> {
        self.read(Self::policy_id(id)?).await
    }
    async fn create(&mut self, spec: &PolicySpec) -> io::Result<PolicyHandle> {
        self.socket.ack(&Self::policy_message(spec, false)?).await?;
        Ok(self.get(&spec.id).await?.handle)
    }
    async fn update(&mut self, handle: &PolicyHandle, spec: &PolicySpec) -> io::Result<()> {
        let request = Self::policy_message(spec, true)?;
        let current = self.read(handle.request()).await?;
        if current.handle.id.as_ref() != Some(&spec.id) {
            // Linux updates locate policies by selectors, not by index.
            // Replacing this native object lets update() repair identities
            // outside the supported model without touching a different index.
            self.delete(handle).await?;
            self.create(spec).await?;
            return Ok(());
        }
        self.socket.ack(&request).await
    }
    async fn delete(&mut self, handle: &PolicyHandle) -> io::Result<()> {
        let request = XfrmMessage::DeletePolicy(handle.request());
        match self.socket.ack(&message(NlmF::ACK, &request)).await {
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
    use crate::model::{PolicyData, PolicyId, PolicyKind, PolicyPriority, Ts};
    use crate::policy::PolicyHandle as _;
    use netlink_packet_core::Emitable;
    use std::collections::HashSet;

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires root; creates a network namespace"]
    async fn global_inventory_and_mutations_use_native_policy_indices() {
        let _namespace = crate::test_netns::Netns::new();
        let mut kernel = LinuxPolicies::new().await.unwrap();
        let mut spec = PolicySpec {
            id: PolicyKey {
                src: "192.0.2.0/24".parse().unwrap(),
                dst: "198.51.100.0/24".parse().unwrap(),
                src_port: 0,
                src_port_mask: 0,
                dst_port: 0,
                dst_port_mask: 0,
                protocol: 0,
                dir: PolicyDirection::Outbound,
                mark: Mark {
                    value: 0x123,
                    mask: 0xfff,
                },
                if_id: 41,
            },
            config: PolicyConfig {
                priority: 100,
                block: true,
                forward_icmp: false,
                template: None,
            },
        };
        let handle = kernel.create(&spec).await.unwrap();
        assert_ne!(handle.index, 0);
        assert_eq!(handle.id(), Some(&spec.id));
        // The index is unique, but omitting XFRM's extra addressing qualifiers
        // cannot retrieve a marked policy bound to a nonzero interface ID.
        let mut bare = handle.request();
        bare.nlas.clear();
        assert!(is_missing(&kernel.read(bare).await.unwrap_err()));
        assert_eq!(
            kernel.read(handle.request()).await.unwrap().handle.index,
            handle.index
        );
        spec.config.priority = 200;
        kernel.update(&handle, &spec).await.unwrap();
        let current = kernel.get(&spec.id).await.unwrap();
        assert_eq!(current.handle.index, handle.index);
        assert_eq!(current.config.as_ref(), Some(&spec.config));

        // Reject unsupported modes before update() can replace an existing
        // policy whose identity differs from the requested one.
        for mode in [
            crate::rpc_api::IpsecMode::Transport,
            crate::rpc_api::IpsecMode::Other(u32::MAX),
        ] {
            let mut rejected = spec.clone();
            rejected.id.dst = "203.0.113.0/24".parse().unwrap();
            rejected.config.template = Some(PolicyTemplate {
                mode,
                src: "192.0.2.1".parse().unwrap(),
                dst: "198.51.100.1".parse().unwrap(),
                reqid: 42,
                spi: 0,
            });
            assert_eq!(
                kernel.create(&rejected).await.unwrap_err().raw_os_error(),
                Some(libc::EOPNOTSUPP)
            );
            assert_eq!(
                kernel
                    .update(&handle, &rejected)
                    .await
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EOPNOTSUPP)
            );
            let unchanged = kernel.get(&spec.id).await.unwrap();
            assert_eq!(unchanged.handle.index, handle.index);
            assert_eq!(unchanged.config.as_ref(), Some(&spec.config));
        }

        // Replace the native object at the same index with a different logical
        // identity. Deletion still targets that index, not the stale selector.
        kernel.delete(&handle).await.unwrap();
        let mut replacement = spec.clone();
        replacement.id.dst = "203.0.113.0/24".parse().unwrap();
        let mut native = LinuxPolicies::policy_spec(&replacement).unwrap();
        native.user_policy_info.index = handle.index;
        kernel
            .socket
            .ack(&message(NlmF::ACK, &XfrmMessage::AddPolicy(native)))
            .await
            .unwrap();
        assert_eq!(
            kernel.get(&replacement.id).await.unwrap().handle.index,
            handle.index
        );
        kernel.delete(&handle).await.unwrap();
        assert!(kernel.list().await.unwrap().is_empty());
        kernel.delete(&handle).await.unwrap();

        // Unknown identities must remain in inventory so empty desired state
        // deletes them too, including native selector scopes we never create.
        let mut native = LinuxPolicies::policy_spec(&spec).unwrap();
        native.user_policy_info.selector.user = 1234;
        kernel
            .socket
            .ack(&message(NlmF::ACK, &XfrmMessage::AddPolicy(native)))
            .await
            .unwrap();
        let unknown = kernel.list().await.unwrap().pop().unwrap();
        assert!(unknown.handle.id().is_none() && unknown.config.is_none());
        // update() chooses replacement when the native selector cannot be
        // represented; the reconciler need not understand Linux's limitation.
        kernel.update(&unknown.handle, &spec).await.unwrap();
        assert_eq!(
            kernel.get(&spec.id).await.unwrap().config.as_ref(),
            Some(&spec.config)
        );
        // Sub policies share the global inventory but need their own type
        // qualifier when deleting by index, even with identical selectors.
        let mut sub = LinuxPolicies::policy_spec(&spec).unwrap();
        sub.nlas.push(Attr::PolicyType(packet::UserPolicyType {
            ptype: packet::XFRM_POLICY_TYPE_SUB,
            ..Default::default()
        }));
        match kernel
            .socket
            .ack(&message(NlmF::ACK, &XfrmMessage::AddPolicy(sub)))
            .await
        {
            Ok(()) => {
                let inventory = kernel.list().await.unwrap();
                assert_eq!(inventory.len(), 2);
                let sub = inventory
                    .iter()
                    .find(|entry| entry.handle.policy_type == packet::XFRM_POLICY_TYPE_SUB)
                    .unwrap();
                assert!(sub.handle.id().is_none());
                kernel.delete(&sub.handle).await.unwrap();
            }
            // CONFIG_XFRM_SUB_POLICY is optional. Linux rejects SUB with
            // EINVAL when it is disabled; the main policy must be unaffected.
            Err(error) => assert_eq!(error.raw_os_error(), Some(libc::EINVAL)),
        }
        assert_eq!(
            kernel.get(&spec.id).await.unwrap().config.as_ref(),
            Some(&spec.config)
        );
        let mut policies = crate::policy::Policies::new(kernel);
        policies.reconcile().await.unwrap();
        // A fresh backend discovers the table without a retained handle map.
        assert!(LinuxPolicies::new()
            .await
            .unwrap()
            .list()
            .await
            .unwrap()
            .is_empty());
    }

    fn is_missing(error: &io::Error) -> bool {
        error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
    }

    #[test]
    fn observations_ignore_usage_metadata_but_preserve_configuration_changes() {
        for (src, dst, prefix) in [
            ("192.0.2.1", "192.0.2.2", 32),
            ("2001:db8::1", "2001:db8::2", 128),
        ] {
            let src = Endpoint::new(src.parse().unwrap(), 0);
            let dst = Endpoint::new(dst.parse().unwrap(), 0);
            let id = PolicyKey::new(&PolicyId {
                src: Ts::from_subnet(src, prefix, 0, 0, u16::MAX).unwrap(),
                dst: Ts::from_subnet(dst, prefix, 0, 0, u16::MAX).unwrap(),
                dir: PolicyDirection::Outbound,
                mark: Mark::default(),
                if_id: 41,
            })
            .unwrap();
            let config = PolicyConfig {
                priority: 100,
                block: false,
                forward_icmp: true,
                template: Some(PolicyTemplate {
                    mode: crate::model::IpsecMode::Iptfs,
                    src: src.address,
                    dst: dst.address,
                    reqid: 42,
                    spi: 0x10203,
                }),
            };
            let mut native = LinuxPolicies::policy_spec(&PolicySpec {
                id: id.clone(),
                config: config.clone(),
            })
            .unwrap();
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
            native.user_policy_info.flags |= packet::XFRM_POLICY_LOCALOK;
            assert_eq!(LinuxPolicies::configuration(&id, &native), None);
            native.user_policy_info.flags &= !packet::XFRM_POLICY_LOCALOK;
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
            let any = Endpoint::new(address.parse().unwrap(), 0);
            let mut id = PolicyId {
                src: Ts::from_subnet(any, 0, protocol, icmp_type << 8, icmp_type << 8).unwrap(),
                dst: Ts::from_subnet(any, 0, 0, 0, u16::MAX).unwrap(),
                dir: PolicyDirection::Outbound,
                mark: Mark::default(),
                if_id: 41,
            };
            let data = PolicyData {
                mode: crate::model::IpsecMode::Tunnel,
                kind: PolicyKind::Ipsec,
                prio: PolicyPriority::Default,
                manual_prio: 0,
                src: any,
                dst: any,
                reqid: 42,
                policy_count: 1,
                esp: Some(0x10203),
                forward_icmp: false,
            };
            let priority = |id: &PolicyId| {
                let spec = PolicySpec::new(id, &data).unwrap();
                let request = LinuxPolicies::policy_message(&spec, false).unwrap();
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
            let host = Endpoint::new(network.parse().unwrap(), 0);
            let id = PolicyId {
                src: Ts::from_subnet(host, prefix, 6, 1024, 2047).unwrap(),
                dst: Ts::from_subnet(host, prefix, 0, 0, u16::MAX).unwrap(),
                dir: PolicyDirection::Outbound,
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
            equivalent.src.from.address = first.parse().unwrap();
            equivalent.src.to.address = last.parse().unwrap();
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
            different.dir = PolicyDirection::Forward;
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
            let host = Endpoint::new(address.parse().unwrap(), 0);
            let src = Ts::from_subnet(host, prefix, protocol, type_code, type_code).unwrap();
            let dst = Ts::from_subnet(host, prefix, 0, 0, u16::MAX).unwrap();
            let selector = selector(
                &PolicyKey::new(&PolicyId {
                    src: src.clone(),
                    dst: dst.clone(),
                    dir: PolicyDirection::Outbound,
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
                assert_eq!(decoded.from.address, src.from.address);
                assert_eq!(decoded.from_port, type_code);
                assert_eq!(decoded.to_port, type_code);
            }

            let mut id = PolicyId {
                src,
                dst,
                dir: PolicyDirection::Outbound,
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
