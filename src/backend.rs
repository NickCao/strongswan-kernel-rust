// SPDX-License-Identifier: GPL-2.0-or-later
use crate::{
    error::{invalid, unsupported},
    interfaces::Interfaces,
    linux::{interfaces::LinuxInterfaces, network::Network, policy::LinuxPolicies, xfrm::LinuxSas},
    model::*,
    policy::Policies,
    rpc_api as rpc,
    sa::{SaChanges, Sas},
};
use std::{collections::HashSet, io};

pub struct Backend {
    pub sas: Sas<LinuxSas>,
    pub net: Network,
    pub policies: Policies<LinuxPolicies>,
    interfaces: Interfaces<LinuxInterfaces>,
}
impl Backend {
    pub fn new(
        prefix: String,
        master_device: Option<String>,
        mtu: u32,
        interface_group: u32,
        config: SessionConfig,
    ) -> io::Result<Self> {
        if !(1280..=65535).contains(&mtu) {
            return Err(invalid());
        }
        let mut net = Network::new()?;
        // Host routes, policy rules and virtual addresses belong to ranet.
        net.config = config;
        Ok(Self {
            sas: Sas::new(LinuxSas::new()?),
            net,
            policies: Policies::new(LinuxPolicies::new()?),
            interfaces: Interfaces::new(
                LinuxInterfaces::new(prefix, interface_group)?,
                master_device,
                mtu,
            ),
        })
    }
    fn desired_interfaces(&self) -> HashSet<u32> {
        self.sas.ids().map(|sa| sa.if_id).collect()
    }
    pub fn cleanup_interfaces(&mut self) -> io::Result<()> {
        self.interfaces.remove_unused(&self.desired_interfaces())
    }
    pub fn reconcile_interfaces(&mut self) -> io::Result<()> {
        self.interfaces.reconcile(&self.desired_interfaces())
    }
    pub fn reconcile_sas(&mut self) -> io::Result<SaChanges> {
        let mut changes = self.sas.reconcile()?;
        // Release the failed tunnel's interface before asking strongSwan to
        // recover, so routing daemons can immediately choose another tunnel.
        if let Err(error) = self.cleanup_interfaces() {
            changes.cleanup_error.get_or_insert(error);
        }
        Ok(changes)
    }
    pub fn install_sa(&mut self, id: rpc::SaId, config: rpc::SaConfig) -> io::Result<()> {
        let id = sa_id(id)?;
        // These checks used to run in the plugin. All options now arrive at
        // this boundary, even when the current backend does not support them.
        if config.mode != 2
            || config.ipcomp != 0
            || config.cpi != 0
            || config.security_label.is_some()
            || config.hw_offload != 0
            || config.cpu != u32::MAX
            || config.forward_icmp
            || restricted_interface(config.interface.as_deref())
        {
            return Err(unsupported());
        }
        if config.lifetime.is_none()
            || config.replay_window > 4096 * 32
            || !(0..=3).contains(&config.copy_dscp)
            || config.reqid == 0
            || config.encryption.name.len() >= 64
            || config.integrity.name.len() >= 64
            || config.encryption.key.len() > 8192
            || config.integrity.key.len() > 8192
        {
            return Err(invalid());
        }
        if config.udp_encapsulation && (id.src.port < 1024 || id.dst.port < 1024) {
            return Err(invalid());
        }
        self.interfaces.ensure(id.if_id)?;
        let result = self.sas.install(&id, &config);
        let cleanup = self.cleanup_interfaces();
        result.and(cleanup)
    }
    pub fn remove_sa(&mut self, id: rpc::SaId) -> io::Result<()> {
        let result = self.sas.remove(&sa_id(id)?);
        let cleanup = self.cleanup_interfaces();
        result.and(cleanup)
    }
    pub fn flush_sas(&mut self) -> io::Result<()> {
        let result = self.sas.clear();
        let cleanup = self.cleanup_interfaces();
        result.and(cleanup)
    }
    pub fn shutdown(&mut self) -> io::Result<()> {
        self.policies.clear();
        let policies = self.policies.reconcile();
        let sas = self.sas.clear();
        let interfaces = self.interfaces.reconcile(&HashSet::new());
        policies.and(sas).and(interfaces)
    }
    pub fn close(&mut self) -> io::Result<()> {
        // Remove bypasses only after all tunnel objects are gone.
        if !self.sas.is_empty() || self.policies.has_tunnel_policies() {
            return Err(io::Error::from_raw_os_error(libc::EBUSY));
        }
        self.flush_sas()?;
        self.policies.clear();
        self.policies.reconcile()
    }
}
fn number<T: TryFrom<i32>>(n: i32) -> io::Result<T> {
    T::try_from(n).map_err(|_| invalid())
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
    if s.dynamic || s.kind != if s.from.is_ipv4() { 7 } else { 8 } {
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
        kind: if s.from.address.is_ipv4() { 7 } else { 8 },
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
        dir: number(p.direction)?,
        src: selector(p.src)?,
        dst: selector(p.dst)?,
        mark: p.mark,
        if_id: p.interface_id,
    };
    if id.dir > 2 || id.if_id == 0 || id.src.from.family() != id.dst.from.family() {
        return Err(invalid());
    }
    Ok(id)
}
pub fn policy_config(p: rpc::PolicyConfig) -> io::Result<PolicyData> {
    let sa = p.sa.ok_or_else(unsupported)?;
    if sa.mode != 2
        || sa.ah.used
        || sa.ipcomp.transform != 0
        || p.hw_offload != 0
        || p.pcpu_acquires
        || p.forward_icmp
    {
        return Err(unsupported());
    }
    let d = PolicyData {
        kind: number(p.kind)?,
        prio: number(p.priority)?,
        manual_prio: p.manual_priority,
        // Policy references use addresses and ports, not IPv6 sockaddr metadata.
        src: policy_endpoint(p.src.ok_or_else(invalid)?)?,
        dst: policy_endpoint(p.dst.ok_or_else(invalid)?)?,
        reqid: sa.reqid,
        policy_count: sa.policy_count,
        esp: sa.esp.used.then_some(sa.esp.spi),
    };
    if !(1..=3).contains(&d.kind)
        || d.prio > 3
        || d.src.family() != d.dst.family()
        || (d.kind == 1 && (d.reqid == 0 || d.esp.is_none()))
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
