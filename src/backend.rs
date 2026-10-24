// SPDX-License-Identifier: GPL-2.0-or-later
use crate::{
    error::{invalid, unsupported},
    interfaces::{InterfaceKernel, Interfaces},
    linux::{interfaces::LinuxInterfaces, network::Network, policy::LinuxPolicies, xfrm::LinuxSas},
    model::*,
    policy::Policies,
    rpc_api as rpc,
    sa::{SaChanges, Sas},
};
use std::{collections::HashSet, io};

pub struct Backend<I: InterfaceKernel = LinuxInterfaces> {
    pub sas: Sas<LinuxSas>,
    pub net: Network,
    pub policies: Policies<LinuxPolicies>,
    interfaces: Interfaces<I>,
}
impl Backend {
    pub async fn new(
        prefix: String,
        master_device: Option<String>,
        mtu: u32,
        interface_group: u32,
        config: SessionConfig,
    ) -> io::Result<Self> {
        if !(1280..=65535).contains(&mtu) {
            return Err(invalid());
        }
        let mut net = Network::new().await?;
        let sas = LinuxSas::new(config.iptfs).await?;
        // Host routes, policy rules and virtual addresses belong to ranet.
        net.config = config;
        Ok(Self {
            sas: Sas::new(sas),
            net,
            policies: Policies::new(LinuxPolicies::new().await?),
            interfaces: Interfaces::new(
                LinuxInterfaces::new(prefix, interface_group).await?,
                master_device,
                mtu,
            ),
        })
    }
}
impl<I: InterfaceKernel> Backend<I> {
    fn desired_interfaces(&self) -> HashSet<u32> {
        self.sas
            .ids()
            .map(|sa| sa.if_id)
            .chain(self.policies.interface_ids())
            .collect()
    }
    pub(crate) async fn cleanup_interface(&mut self, if_id: u32) -> io::Result<()> {
        if self.sas.ids().any(|sa| sa.if_id == if_id)
            || self.policies.interface_ids().any(|id| id == if_id)
        {
            return Ok(());
        }
        self.interfaces.remove(if_id).await
    }
    pub(crate) async fn cleanup_interfaces(&mut self, candidates: &HashSet<u32>) -> io::Result<()> {
        let desired = self.desired_interfaces();
        let mut first_error = None;
        for id in candidates.difference(&desired) {
            if let Err(error) = self.interfaces.remove(*id).await {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
    pub async fn reconcile_interfaces(&mut self) -> io::Result<()> {
        self.interfaces.reconcile(&self.desired_interfaces()).await
    }
    pub async fn reconcile_sas(&mut self) -> io::Result<SaChanges> {
        let mut changes = self.sas.reconcile().await?;
        // Policies, including traps, keep their interfaces after SA loss.
        // Release only interfaces that have no remaining owner.
        let candidates = changes.expired.iter().map(|id| id.if_id).collect();
        if let Err(error) = self.cleanup_interfaces(&candidates).await {
            changes.cleanup_error.get_or_insert(error);
        }
        Ok(changes)
    }
    pub async fn install_policy(
        &mut self,
        id: rpc::PolicyId,
        config: rpc::PolicyConfig,
    ) -> io::Result<()> {
        let id = policy_id(id)?;
        let if_id = id.if_id;
        let data = policy_config(config)?;
        let result = async {
            self.interfaces.ensure(id.if_id).await?;
            self.policies.add_policy(id, data).await
        }
        .await;
        // Failed installations release only their temporary interface.
        // Periodic reconciliation retries interrupted cleanup.
        if result.is_err() {
            if let Err(error) = self.cleanup_interface(if_id).await {
                eprintln!("kernel-daemon: interface cleanup after policy installation: {error}");
            }
        }
        result
    }
    pub async fn remove_policy(
        &mut self,
        id: rpc::PolicyId,
        config: rpc::PolicyConfig,
    ) -> io::Result<()> {
        let id = policy_id(id)?;
        let result = self
            .policies
            .delete_policy(&id, &policy_config(config)?)
            .await;
        let cleanup = self.cleanup_interface(id.if_id).await;
        result.and(cleanup)
    }
    pub async fn flush_policies(&mut self) -> io::Result<()> {
        let candidates = self.policies.interface_ids().collect();
        let result = self.policies.flush_policies().await;
        let cleanup = self.cleanup_interfaces(&candidates).await;
        result.and(cleanup)
    }
    pub async fn install_sa(&mut self, id: rpc::SaId, config: rpc::SaConfig) -> io::Result<()> {
        let id = sa_id(id)?;
        // These checks used to run in the plugin. All options now arrive at
        // this boundary, even when the current backend does not support them.
        if config.ipcomp != IpcompTransform::None
            || config.cpi != 0
            || config.security_label.is_some()
            || config.hw_offload != HwOffload::No
            || config.cpu != u32::MAX
            || restricted_interface(config.interface.as_deref())
        {
            return Err(unsupported());
        }
        if config.lifetime.is_none()
            || config.replay_window > 4096 * 32
            || matches!(config.copy_dscp, DscpCopy::Other(_))
            || config.reqid == 0
            || config.encryption.name.len() >= netlink_packet_xfrm::XFRM_ALG_NAME_LEN
            || config.integrity.name.len() >= netlink_packet_xfrm::XFRM_ALG_AUTH_NAME_LEN
            || config.encryption.key.len() > 8192
            || config.integrity.key.len() > 8192
        {
            return Err(invalid());
        }
        if config.udp_encapsulation && (id.src.port < 1024 || id.dst.port < 1024) {
            return Err(invalid());
        }
        self.interfaces.ensure(id.if_id).await?;
        let result = self.sas.install(&id, &config).await;
        // Preserve the installation result if rolling back its interface fails.
        if result.is_err() {
            if let Err(error) = self.cleanup_interface(id.if_id).await {
                eprintln!("kernel-daemon: interface cleanup after SA installation: {error}");
            }
        }
        result
    }
    pub async fn remove_sa(&mut self, id: rpc::SaId) -> io::Result<()> {
        let id = sa_id(id)?;
        let result = self.sas.remove(&id).await;
        let cleanup = self.cleanup_interface(id.if_id).await;
        result.and(cleanup)
    }
    pub async fn flush_sas(&mut self) -> io::Result<()> {
        let candidates = self.sas.ids().map(|id| id.if_id).collect();
        let result = self.sas.clear().await;
        let cleanup = self.cleanup_interfaces(&candidates).await;
        result.and(cleanup)
    }
    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.policies.clear();
        let policies = self.policies.reconcile().await;
        let sas = self.sas.clear().await;
        let interfaces = self.interfaces.reconcile(&HashSet::new()).await;
        policies.and(sas).and(interfaces)
    }
    pub async fn close(&mut self) -> io::Result<()> {
        // Remove bypasses only after all tunnel objects are gone.
        if !self.sas.is_empty() || self.policies.has_tunnel_policies() {
            return Err(io::Error::from_raw_os_error(libc::EBUSY));
        }
        self.flush_sas().await?;
        // Session teardown also discovers leftovers from interrupted targeted
        // cleanup, including owned interfaces renamed by another process.
        self.reconcile_interfaces().await?;
        self.policies.clear();
        self.policies.reconcile().await
    }
}
pub fn validate_endpoint(endpoint: Endpoint) -> io::Result<Endpoint> {
    std::net::SocketAddr::try_from(&endpoint).map_err(|_| invalid())?;
    Ok(endpoint)
}
pub fn sa_id(id: rpc::SaId) -> io::Result<SaId> {
    if id.protocol != 50 {
        return Err(unsupported());
    }
    let s = SaId {
        src: validate_endpoint(id.src)?,
        dst: validate_endpoint(id.dst)?,
        spi: id.spi,
        proto: id.protocol,
        mark: id.mark,
        if_id: id.interface_id,
    };
    if s.src.family() != s.dst.family() || s.spi < 256 || s.if_id == 0 {
        return Err(invalid());
    }
    Ok(s)
}
pub fn selector(s: rpc::Selector) -> io::Result<Ts> {
    let from = Endpoint::new(s.from, 0);
    let to = Endpoint::new(s.to, 0);
    if s.dynamic
        || s.kind
            != if s.from.is_ipv4() {
                SelectorKind::Ipv4Range
            } else {
                SelectorKind::Ipv6Range
            }
    {
        return Err(unsupported());
    }
    let ts = Ts {
        from,
        to,
        proto: s.protocol,
        from_port: s.from_port,
        to_port: s.to_port,
    };
    if ts.from.family() != ts.to.family()
        || ts.from.address > ts.to.address
        || ts.from_port > ts.to_port
    {
        return Err(invalid());
    }
    // XFRM accepts prefixes and aligned port masks, not arbitrary ranges.
    let (net, prefix) = ts.subnet();
    let represented = Ts::from_subnet(net, prefix, ts.proto, ts.from_port, ts.to_port)?;
    let (port, mask) = ts.ports();
    if represented.from != ts.from
        || represented.to != ts.to
        || port != ts.from_port
        || port | !mask != ts.to_port
    {
        return Err(invalid());
    }
    Ok(ts)
}
pub fn rpc_selector(s: Ts) -> rpc::Selector {
    rpc::Selector {
        kind: if s.from.address.is_ipv4() {
            SelectorKind::Ipv4Range
        } else {
            SelectorKind::Ipv6Range
        },
        dynamic: false,
        from: s.from.address,
        to: s.to.address,
        protocol: s.proto,
        from_port: s.from_port,
        to_port: s.to_port,
    }
}
pub fn policy_id(p: rpc::PolicyId) -> io::Result<PolicyId> {
    if p.security_label.is_some() || restricted_interface(p.interface.as_deref()) {
        return Err(unsupported());
    }
    let id = PolicyId {
        dir: p.direction,
        src: selector(p.src)?,
        dst: selector(p.dst)?,
        mark: p.mark,
        if_id: p.interface_id,
    };
    if matches!(id.dir, PolicyDirection::Other(_))
        || id.if_id == 0
        || id.src.from.family() != id.dst.from.family()
    {
        return Err(invalid());
    }
    Ok(id)
}
pub fn policy_config(p: rpc::PolicyConfig) -> io::Result<PolicyData> {
    let sa = p.sa.ok_or_else(unsupported)?;
    if !matches!(sa.mode, IpsecMode::Tunnel | IpsecMode::Iptfs)
        || sa.ah.used
        || sa.ipcomp.transform != IpcompTransform::None
        || p.hw_offload != HwOffload::No
        || p.pcpu_acquires
    {
        return Err(unsupported());
    }
    let d = PolicyData {
        mode: sa.mode,
        kind: p.kind,
        prio: p.priority,
        manual_prio: p.manual_priority,
        // Policy references use addresses and ports, not IPv6 sockaddr metadata.
        src: policy_endpoint(p.src.ok_or_else(invalid)?)?,
        dst: policy_endpoint(p.dst.ok_or_else(invalid)?)?,
        reqid: sa.reqid,
        policy_count: sa.policy_count,
        esp: sa.esp.used.then_some(sa.esp.spi),
        forward_icmp: p.forward_icmp,
    };
    if matches!(d.kind, PolicyKind::Other(_))
        || matches!(d.prio, PolicyPriority::Other(_))
        || d.src.family() != d.dst.family()
        || (d.kind == PolicyKind::Ipsec && (d.reqid == 0 || d.esp.is_none()))
    {
        return Err(invalid());
    }
    Ok(d)
}
fn restricted_interface(interface: Option<&str>) -> bool {
    interface.is_some_and(|name| !name.is_empty())
}
fn policy_endpoint(endpoint: Endpoint) -> io::Result<Endpoint> {
    let endpoint = validate_endpoint(endpoint)?;
    Ok(Endpoint::new(endpoint.address, endpoint.port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        interfaces::{InterfaceSpec, ObservedInterface},
        rpc_api::{Algorithm, EncryptionAlgorithm, IntegrityAlgorithm, Lifetime, LifetimeLimit},
        sa::SaKernel,
    };
    use rstest::rstest;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct InterruptedCleanup {
        kernel: LinuxInterfaces,
        lookups: Arc<AtomicUsize>,
        interrupt: bool,
    }
    impl InterfaceKernel for InterruptedCleanup {
        type Handle = <LinuxInterfaces as InterfaceKernel>::Handle;

        async fn list(&mut self) -> io::Result<Vec<ObservedInterface<Self::Handle>>> {
            panic!("individual SA operations must not list interfaces")
        }
        async fn get(
            &mut self,
            id: crate::interfaces::InterfaceId,
        ) -> io::Result<Option<ObservedInterface<Self::Handle>>> {
            // The first lookup prepares the interface. Interrupt the lookup
            // used to roll back a rejected installation.
            if self.lookups.fetch_add(1, Ordering::SeqCst) == 1 && self.interrupt {
                return Err(io::Error::from_raw_os_error(libc::EINTR));
            }
            self.kernel.get(id).await
        }
        async fn create(&mut self, spec: &InterfaceSpec) -> io::Result<Self::Handle> {
            self.kernel.create(spec).await
        }
        async fn update(&mut self, handle: &Self::Handle, spec: &InterfaceSpec) -> io::Result<()> {
            self.kernel.update(handle, spec).await
        }
        async fn delete(&mut self, handle: &Self::Handle) -> io::Result<()> {
            self.kernel.delete(handle).await
        }
    }

    #[rstest]
    #[case::installed(true)]
    #[case::rejected(false)]
    #[ignore = "requires root; creates a network namespace"]
    #[tokio::test(flavor = "current_thread")]
    async fn sa_installation_uses_targeted_rollback_and_preserves_its_result(
        #[case] successful: bool,
    ) {
        let _namespace = crate::test_netns::Netns::new();
        let lookups = Arc::new(AtomicUsize::new(0));
        let kernel = async || LinuxInterfaces::new("tst".into(), 17227).await.unwrap();
        let mut backend = Backend {
            sas: Sas::new(LinuxSas::new(Default::default()).await.unwrap()),
            net: Network::new().await.unwrap(),
            policies: Policies::new(LinuxPolicies::new().await.unwrap()),
            interfaces: Interfaces::new(
                InterruptedCleanup {
                    kernel: kernel().await,
                    lookups: lookups.clone(),
                    interrupt: !successful,
                },
                None,
                1400,
            ),
        };
        let id = || rpc::SaId {
            src: Endpoint::new("192.0.2.1".parse().unwrap(), 13000),
            dst: Endpoint::new("192.0.2.2".parse().unwrap(), 13000),
            spi: 0x10203,
            protocol: 50,
            mark: Mark::default(),
            interface_id: 41,
        };
        let limit = || LifetimeLimit {
            life: 0,
            rekey: 0,
            jitter: 0,
        };
        let config = SaConfig {
            reqid: 42,
            acquire_sequence: 0,
            mode: IpsecMode::Tunnel,
            src_selectors: None,
            dst_selectors: None,
            interface: None,
            encryption: Algorithm {
                id: if successful {
                    EncryptionAlgorithm::AesGcmIcv16
                } else {
                    EncryptionAlgorithm::Other(u16::MAX)
                },
                name: String::new(),
                key: vec![0; 20],
            },
            integrity: Algorithm {
                id: IntegrityAlgorithm::Undefined,
                name: String::new(),
                key: Vec::new(),
            },
            lifetime: Some(Lifetime {
                time: limit(),
                bytes: limit(),
                packets: limit(),
            }),
            replay_window: 32,
            ipcomp: IpcompTransform::None,
            cpi: 0,
            cpu: u32::MAX,
            hw_offload: HwOffload::No,
            security_label: None,
            esn: false,
            udp_encapsulation: true,
            output_mark: Mark::default(),
            tfc: 0,
            copy_df: true,
            copy_ecn: true,
            copy_dscp: DscpCopy::OutOnly,
            iptfs_dont_fragment: false,
            forward_icmp: false,
            initiator: false,
            inbound: false,
            update: false,
        };
        let result = backend.install_sa(id(), config).await;
        assert_eq!(
            lookups.load(Ordering::SeqCst),
            if successful { 1 } else { 2 }
        );
        if successful {
            result.unwrap();
            backend.sas.query(&sa_id(id()).unwrap()).await.unwrap();
        } else {
            assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EOPNOTSUPP));
        }
        let mut native = LinuxSas::new(Default::default()).await.unwrap();
        assert_eq!(native.list().await.unwrap().len(), usize::from(successful));
        // A later cleanup retries the interrupted lookup. It retains an
        // installed SA's interface and removes a rejected install's interface.
        backend.cleanup_interface(41).await.unwrap();
        assert_eq!(
            kernel().await.list().await.unwrap().len(),
            usize::from(successful)
        );
        if successful {
            backend.remove_sa(id()).await.unwrap();
        }
        assert!(native.list().await.unwrap().is_empty());
        assert!(kernel().await.list().await.unwrap().is_empty());
    }

    #[rstest]
    #[case::any_port(0, u16::MAX, true)]
    #[case::single_port(443, 443, true)]
    #[case::aligned_range(1024, 2047, true)]
    #[case::unaligned_range(1025, 2047, false)]
    #[case::reversed_range(2047, 1024, false)]
    fn selector_port_ranges(
        #[values("192.0.2.0/24", "2001:db8::/64")] cidr: ipnet::IpNet,
        #[case] from_port: u16,
        #[case] to_port: u16,
        #[case] valid: bool,
    ) {
        let input = rpc::Selector {
            kind: if cidr.addr().is_ipv4() {
                SelectorKind::Ipv4Range
            } else {
                SelectorKind::Ipv6Range
            },
            dynamic: false,
            from: cidr.network(),
            to: cidr.broadcast(),
            protocol: libc::IPPROTO_TCP as u8,
            from_port,
            to_port,
        };
        let actual = selector(input.clone());
        if valid {
            assert_eq!(rpc_selector(actual.unwrap()), input);
        } else {
            assert_eq!(actual.unwrap_err().raw_os_error(), Some(libc::EINVAL));
        }
    }

    #[rstest]
    #[case::ipv4_range("192.0.2.1", "192.0.2.254", false)]
    #[case::ipv6_range("2001:db8::1", "2001:db8::ffff", false)]
    #[case::mixed_families("192.0.2.1", "2001:db8::1", false)]
    #[case::reversed_range("192.0.2.2", "192.0.2.1", false)]
    #[case::ipv4_host("192.0.2.1", "192.0.2.1", true)]
    #[case::ipv6_host("2001:db8::1", "2001:db8::1", true)]
    fn selector_address_ranges(
        #[case] from: std::net::IpAddr,
        #[case] to: std::net::IpAddr,
        #[case] valid: bool,
    ) {
        let input = rpc::Selector {
            kind: if from.is_ipv4() {
                SelectorKind::Ipv4Range
            } else {
                SelectorKind::Ipv6Range
            },
            dynamic: false,
            from,
            to,
            protocol: 0,
            from_port: 0,
            to_port: u16::MAX,
        };
        let actual = selector(input.clone());
        if valid {
            assert_eq!(rpc_selector(actual.unwrap()), input);
        } else {
            assert_eq!(actual.unwrap_err().raw_os_error(), Some(libc::EINVAL));
        }
    }

    #[test]
    fn shared_endpoints_retain_metadata_while_sa_keys_keep_native_identity() {
        let source = Endpoint {
            address: "2001:db8::1".parse().unwrap(),
            port: 13000,
            flow_info: 0x12345,
            scope_id: 17,
        };
        let destination = Endpoint {
            address: "2001:db8::2".parse().unwrap(),
            ..source
        };
        let id = sa_id(rpc::SaId {
            src: source,
            dst: destination,
            spi: 0x10203,
            protocol: 50,
            mark: Mark {
                value: 0x1234,
                mask: 0xff,
            },
            interface_id: 41,
        })
        .unwrap();
        assert_eq!(id.src, source);
        assert_eq!(id.dst, destination);
        let mut same_native_sa = id.clone();
        same_native_sa.src.port += 1;
        same_native_sa.src.scope_id += 1;
        same_native_sa.dst.flow_info += 1;
        same_native_sa.mark.value ^= 0xff00;
        assert_eq!(id.key(), same_native_sa.key());
        same_native_sa.dst.address = "2001:db8::3".parse().unwrap();
        assert_ne!(id.key(), same_native_sa.key());
    }

    #[test]
    fn sharing_endpoints_keeps_ipv4_sockaddr_validation() {
        let endpoint = Endpoint {
            scope_id: 17,
            ..Endpoint::new("192.0.2.1".parse().unwrap(), 13000)
        };
        assert_eq!(
            validate_endpoint(endpoint).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
