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
        interfaces_use: String,
        interfaces_ignore: String,
    ) -> io::Result<Self> {
        if !(1280..=65535).contains(&mtu) {
            return Err(invalid());
        }
        let mut net = Network::new()?;
        // Host routes, policy rules and virtual addresses belong to ranet.
        net.config = Config {
            interfaces_use,
            interfaces_ignore,
        };
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
        let lifetime = config.lifetime.as_ref().ok_or_else(invalid)?;
        // strongSwan has already applied jitter to these rekey limits. Tunnel
        // SAs use policies for selection; their selector lists are not installed.
        let data = AddSa {
            reqid: config.reqid,
            seq: config.acquire_sequence,
            lifetime: [
                lifetime.time.life,
                lifetime.time.rekey,
                lifetime.bytes.life,
                lifetime.bytes.rekey,
                lifetime.packets.life,
                lifetime.packets.rekey,
            ],
            enc_alg: config.encryption.id,
            enc_key: &config.encryption.key,
            int_alg: config.integrity.id,
            int_key: &config.integrity.key,
            enc_name: config.encryption.name.clone(),
            int_name: config.integrity.name.clone(),
            replay_window: config.replay_window,
            tfc: config.tfc,
            encap: config.udp_encapsulation,
            mark: mark(config.output_mark),
            esn: config.esn,
            copy_df: config.copy_df,
            copy_ecn: config.copy_ecn,
            copy_dscp: number(config.copy_dscp)?,
            inbound: config.inbound,
            update: config.update,
        };
        if data.replay_window > 4096 * 32
            || data.copy_dscp > 3
            || data.reqid == 0
            || data.enc_name.len() >= 64
            || data.int_name.len() >= 64
            || data.enc_key.len() > 8192
            || data.int_key.len() > 8192
        {
            return Err(invalid());
        }
        if data.encap && (id.src.port < 1024 || id.dst.port < 1024) {
            return Err(invalid());
        }
        self.interfaces.ensure(id.if_id)?;
        let result = self.sas.install(&id, &data);
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
pub fn host(h: rpc::Endpoint) -> io::Result<Host> {
    let address = std::net::SocketAddr::try_from(&h).map_err(|_| invalid())?;
    Ok(Host {
        ip: address.ip(),
        port: address.port(),
    })
}
pub fn endpoint(h: Host) -> rpc::Endpoint {
    rpc::Endpoint {
        address: h.ip,
        port: h.port,
        flow_info: 0,
        scope_id: 0,
    }
}
fn mark(m: rpc::Mark) -> Mark {
    Mark {
        value: m.value,
        mask: m.mask,
    }
}
pub fn sa_id(id: rpc::SaId) -> io::Result<SaId> {
    if id.protocol != 50 {
        return Err(unsupported());
    }
    let s = SaId {
        src: host(id.src)?,
        dst: host(id.dst)?,
        spi: id.spi,
        proto: id.protocol,
        mark: mark(id.mark),
        if_id: id.interface_id,
    };
    if s.src.family() != s.dst.family() || s.spi < 256 || s.if_id == 0 {
        return Err(invalid());
    }
    Ok(s)
}
pub fn selector(s: rpc::Selector) -> io::Result<Ts> {
    let from = Host {
        ip: s.from,
        port: 0,
    };
    let to = Host { ip: s.to, port: 0 };
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
    if ts.from.family() != ts.to.family() || ts.from.ip > ts.to.ip || ts.from_port > ts.to_port {
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
        kind: if s.from.ip.is_ipv4() { 7 } else { 8 },
        dynamic: false,
        from: s.from.ip,
        to: s.to.ip,
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
        mark: mark(p.mark),
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
        src: host(p.src.ok_or_else(invalid)?)?,
        dst: host(p.dst.ok_or_else(invalid)?)?,
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
