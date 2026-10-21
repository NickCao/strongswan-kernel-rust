// SPDX-License-Identifier: GPL-2.0-or-later
use crate::error::invalid;
pub use crate::rpc_api::{Endpoint, Mark, SaConfig, SessionConfig};
use ipnet::IpNet;
use std::io;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ts {
    pub from: Endpoint,
    pub to: Endpoint,
    pub proto: u8,
    pub from_port: u16,
    pub to_port: u16,
}
impl Ts {
    pub fn subnet(&self) -> (Endpoint, u8) {
        let mut subnet = IpNet::from(self.from.address);
        while !subnet.contains(&self.to.address) {
            // Traffic selector validation requires matching address families.
            subnet = subnet.supernet().unwrap();
        }
        (Endpoint::new(subnet.network(), 0), subnet.prefix_len())
    }
    pub fn ports(&self) -> (u16, u16) {
        let bits = (self.from_port ^ self.to_port).leading_zeros();
        let mask = if bits == 0 {
            0
        } else {
            u16::MAX << (16 - bits)
        };
        (self.from_port & mask, mask)
    }
    pub fn from_subnet(
        host: Endpoint,
        prefix: u8,
        proto: u8,
        from_port: u16,
        to_port: u16,
    ) -> io::Result<Self> {
        let subnet = IpNet::new(host.address, prefix).map_err(|_| invalid())?;
        let from = Endpoint::new(subnet.network(), 0);
        let to = Endpoint::new(subnet.broadcast(), 0);
        Ok(Self {
            from,
            to,
            proto,
            from_port,
            to_port,
        })
    }
}
pub fn network(host: &Endpoint, prefix: u8) -> Endpoint {
    Endpoint::new(IpNet::new(host.address, prefix).unwrap().network(), 0)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SaId {
    pub src: Endpoint,
    pub dst: Endpoint,
    pub spi: u32,
    pub proto: u8,
    pub mark: Mark,
    pub if_id: u32,
}
impl SaId {
    pub fn key(&self) -> Self {
        Self {
            // Native SA identity ignores UDP ports and IPv6 sockaddr metadata.
            src: Endpoint::new(self.src.address, 0),
            dst: Endpoint::new(self.dst.address, 0),
            mark: Mark {
                value: self.mark.value & self.mark.mask,
                mask: self.mark.mask,
            },
            ..self.clone()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PolicyId {
    pub dir: u8,
    pub src: Ts,
    pub dst: Ts,
    pub mark: Mark,
    pub if_id: u32,
}
/// One strongSwan policy reference, retained for priority selection and exact
/// removal. Multiple references may share one installed policy during rekeying.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyData {
    pub kind: u8,
    pub prio: u8,
    pub manual_prio: u32,
    pub src: Endpoint,
    pub dst: Endpoint,
    pub reqid: u32,
    pub policy_count: u32,
    pub esp: Option<u32>,
    pub forward_icmp: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selector_masks() {
        let ts = Ts {
            from: Endpoint::new("10.0.1.3".parse().unwrap(), 0),
            to: Endpoint::new("10.0.1.254".parse().unwrap(), 0),
            proto: 6,
            from_port: 1024,
            to_port: 2047,
        };
        assert_eq!(ts.subnet().0.address.to_string(), "10.0.1.0");
        assert_eq!(ts.subnet().1, 24);
        assert_eq!(ts.ports(), (1024, 0xfc00));
        let mut single = ts.clone();
        single.to_port = single.from_port;
        assert_eq!(single.ports(), (1024, 0xffff));
        let ipv6 = Ts::from_subnet(
            Endpoint::new("fd00:1234::".parse().unwrap(), 0),
            64,
            0,
            0,
            65535,
        )
        .unwrap();
        assert_eq!(ipv6.subnet().1, 64);
    }
}
