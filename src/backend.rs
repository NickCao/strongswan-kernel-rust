// SPDX-License-Identifier: GPL-2.0-or-later
use crate::{
    error::invalid,
    interfaces::Interfaces,
    linux::{interfaces::LinuxInterfaces, network::Network, policy::LinuxPolicies, xfrm::Xfrm},
    model::*,
    policy::Policies,
    rpc_api as rpc,
};
use std::{collections::HashSet, io};
use zeroize::Zeroizing;

pub struct Backend {
    pub xfrm: Xfrm,
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
            xfrm: Xfrm::new()?,
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
        self.xfrm.sas.iter().map(|sa| sa.if_id).collect()
    }
    pub fn cleanup_interfaces(&mut self) -> io::Result<()> {
        self.interfaces.remove_unused(&self.desired_interfaces())
    }
    pub fn reconcile_interfaces(&mut self) -> io::Result<()> {
        self.interfaces.reconcile(&self.desired_interfaces())
    }
    pub fn install_sa(&mut self, id: rpc::SaId, config: rpc::SaConfig) -> io::Result<()> {
        let id = sa_id(id)?;
        let enc = decode_key(&config.encryption.key)?;
        let auth = decode_key(&config.integrity.key)?;
        let data = AddSa {
            reqid: number(config.reqid)?,
            seq: number(config.acquireSequence)?,
            lifetime: [
                number(config.lifetime.timeLife)?,
                number(config.lifetime.timeRekey)?,
                decimal(&config.lifetime.byteLife)?,
                decimal(&config.lifetime.byteRekey)?,
                decimal(&config.lifetime.packetLife)?,
                decimal(&config.lifetime.packetRekey)?,
            ],
            enc_alg: number(config.encryption.id)?,
            enc_key: &enc,
            int_alg: number(config.integrity.id)?,
            int_key: &auth,
            enc_name: config.encryption.name.clone(),
            int_name: config.integrity.name.clone(),
            replay_window: number(config.replayWindow)?,
            tfc: number(config.tfc)?,
            encap: config.udpEncapsulation,
            mark: mark(config.outputMark)?,
            esn: config.esn,
            copy_df: config.copyDf,
            copy_ecn: config.copyEcn,
            copy_dscp: number(config.copyDscp)?,
            inbound: config.inbound,
            update: config.update,
        };
        if data.replay_window > 4096 * 32
            || data.copy_dscp > 3
            || data.reqid == 0
            || data.enc_name.len() >= 64
            || data.int_name.len() >= 64
        {
            return Err(invalid());
        }
        if data.encap && (id.src.port < 1024 || id.dst.port < 1024) {
            return Err(invalid());
        }
        self.interfaces.ensure(id.if_id)?;
        let result = self.xfrm.add_sa(&id, &data);
        let cleanup = self.cleanup_interfaces();
        result.and(cleanup)
    }
    pub fn remove_sa(&mut self, id: rpc::SaId) -> io::Result<()> {
        let result = self.xfrm.delete_sa(&sa_id(id)?);
        let cleanup = self.cleanup_interfaces();
        result.and(cleanup)
    }
    pub fn flush_sas(&mut self) -> io::Result<()> {
        let result = self.xfrm.flush_sas();
        let cleanup = self.cleanup_interfaces();
        result.and(cleanup)
    }
    pub fn shutdown(&mut self) -> io::Result<()> {
        self.policies.clear();
        let policies = self.policies.reconcile();
        let interfaces = self.interfaces.reconcile(&HashSet::new());
        // SA and SPI-reservation cleanup will join this path when their
        // ownership and reconciliation are managed by a controller too.
        policies.and(interfaces)
    }
    pub fn close(&mut self) -> io::Result<()> {
        // Remove bypasses only after all tunnel objects are gone.
        if !self.xfrm.sas.is_empty() || self.policies.has_tunnel_policies() {
            return Err(io::Error::from_raw_os_error(libc::EBUSY));
        }
        self.flush_sas()?;
        self.policies.remove_bypasses()
    }
}
pub fn number<T: TryFrom<i64>>(n: i64) -> io::Result<T> {
    T::try_from(n).map_err(|_| invalid())
}
fn decimal(s: &str) -> io::Result<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    s.parse().map_err(|_| invalid())
}
pub fn host(h: rpc::Endpoint) -> io::Result<Host> {
    Ok(Host {
        ip: h.address.parse().map_err(|_| invalid())?,
        port: number(h.port)?,
    })
}
pub fn endpoint(h: Host) -> rpc::Endpoint {
    rpc::Endpoint {
        address: h.ip.to_string(),
        port: h.port.into(),
    }
}
fn mark(m: rpc::Mark) -> io::Result<Mark> {
    Ok(Mark {
        value: number(m.value)?,
        mask: number(m.mask)?,
    })
}
pub fn sa_id(id: rpc::SaId) -> io::Result<SaId> {
    let s = SaId {
        src: host(id.src)?,
        dst: host(id.dst)?,
        spi: number(id.spi)?,
        proto: 50,
        mark: mark(id.mark)?,
        if_id: number(id.interfaceId)?,
    };
    if s.src.family() != s.dst.family() || s.spi < 256 || s.if_id == 0 {
        return Err(invalid());
    }
    Ok(s)
}
pub fn selector(s: rpc::Selector) -> io::Result<Ts> {
    let from = host(rpc::Endpoint {
        address: s.from,
        port: 0,
    })?;
    let to = host(rpc::Endpoint {
        address: s.to,
        port: 0,
    })?;
    let ts = Ts {
        from,
        to,
        proto: number(s.protocol)?,
        from_port: number(s.fromPort)?,
        to_port: number(s.toPort)?,
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
        from: s.from.ip.to_string(),
        to: s.to.ip.to_string(),
        protocol: s.proto.into(),
        fromPort: s.from_port.into(),
        toPort: s.to_port.into(),
    }
}
pub fn policy_id(p: rpc::PolicyId) -> io::Result<PolicyId> {
    let id = PolicyId {
        dir: number(p.direction)?,
        src: selector(p.src)?,
        dst: selector(p.dst)?,
        mark: mark(p.mark)?,
        if_id: number(p.interfaceId)?,
    };
    if id.dir > 2 || id.if_id == 0 || id.src.from.family() != id.dst.from.family() {
        return Err(invalid());
    }
    Ok(id)
}
pub fn policy_config(p: rpc::PolicyConfig) -> io::Result<PolicyData> {
    let d = PolicyData {
        kind: number(p.kind)?,
        prio: number(p.priority)?,
        manual_prio: number(p.manualPriority)?,
        src: host(p.src)?,
        dst: host(p.dst)?,
        reqid: number(p.reqid)?,
        policy_count: number(p.policyCount)?,
        esp: p.espSpi.map(number).transpose()?,
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
fn decode_key(s: &str) -> io::Result<Zeroizing<Vec<u8>>> {
    if s.len() > 16384 {
        return Err(invalid());
    }
    hex::decode(s).map(Zeroizing::new).map_err(|_| invalid())
}
