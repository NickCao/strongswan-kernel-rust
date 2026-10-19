// SPDX-License-Identifier: GPL-2.0-or-later
use crate::error::invalid;
use ipnet::IpNet;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Host {
    pub ip: IpAddr,
    pub port: u16,
}
impl Host {
    pub fn family(&self) -> u16 {
        match self.ip {
            IpAddr::V4(_) => libc::AF_INET as _,
            IpAddr::V6(_) => libc::AF_INET6 as _,
        }
    }
    pub fn bits(&self) -> u8 {
        if self.ip.is_ipv4() {
            32
        } else {
            128
        }
    }
    pub fn any(family: u16) -> io::Result<Self> {
        let ip = match family as i32 {
            libc::AF_INET => Ipv4Addr::UNSPECIFIED.into(),
            libc::AF_INET6 => Ipv6Addr::UNSPECIFIED.into(),
            _ => return Err(invalid()),
        };
        Ok(Self { ip, port: 0 })
    }
    pub fn without_port(&self) -> Self {
        Self {
            ip: self.ip,
            port: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ts {
    pub from: Host,
    pub to: Host,
    pub proto: u8,
    pub from_port: u16,
    pub to_port: u16,
}
impl Ts {
    pub fn subnet(&self) -> (Host, u8) {
        let mut subnet = IpNet::from(self.from.ip);
        while !subnet.contains(&self.to.ip) {
            // Traffic selector validation requires matching address families.
            subnet = subnet.supernet().unwrap();
        }
        (
            Host {
                ip: subnet.network(),
                port: 0,
            },
            subnet.prefix_len(),
        )
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
    pub fn includes(&self, host: &Host) -> bool {
        self.from.ip <= host.ip && host.ip <= self.to.ip
    }
    pub fn from_subnet(
        host: Host,
        prefix: u8,
        proto: u8,
        from_port: u16,
        to_port: u16,
    ) -> io::Result<Self> {
        let subnet = IpNet::new(host.ip, prefix).map_err(|_| invalid())?;
        let from = Host {
            ip: subnet.network(),
            port: 0,
        };
        let to = Host {
            ip: subnet.broadcast(),
            port: 0,
        };
        Ok(Self {
            from,
            to,
            proto,
            from_port,
            to_port,
        })
    }
}
pub fn network(host: &Host, prefix: u8) -> Host {
    Host {
        ip: IpNet::new(host.ip, prefix).unwrap().network(),
        port: 0,
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Mark {
    pub value: u32,
    pub mask: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SaId {
    pub src: Host,
    pub dst: Host,
    pub spi: u32,
    pub proto: u8,
    pub mark: Mark,
    pub if_id: u32,
}
impl SaId {
    pub fn key(&self) -> Self {
        Self {
            src: self.src.without_port(),
            dst: self.dst.without_port(),
            mark: Mark {
                value: self.mark.value & self.mark.mask,
                mask: self.mark.mask,
            },
            ..self.clone()
        }
    }
}

pub struct AddSa<'a> {
    pub reqid: u32,
    pub seq: u32,
    pub lifetime: [u64; 6],
    pub enc_alg: u16,
    pub enc_key: &'a [u8],
    pub int_alg: u16,
    pub int_key: &'a [u8],
    pub enc_name: String,
    pub int_name: String,
    pub replay_window: u32,
    pub tfc: u32,
    pub encap: bool,
    pub mark: Mark,
    pub esn: bool,
    pub copy_df: bool,
    pub copy_ecn: bool,
    pub copy_dscp: u8,
    pub inbound: bool,
    pub update: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PolicyId {
    pub dir: u8,
    pub src: Ts,
    pub dst: Ts,
    pub mark: Mark,
    pub if_id: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyData {
    pub kind: u8,
    pub prio: u8,
    pub manual_prio: u32,
    pub src: Host,
    pub dst: Host,
    pub reqid: u32,
    pub policy_count: u32,
    pub esp: Option<u32>,
}

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub interfaces_use: String,
    pub interfaces_ignore: String,
}
impl Config {
    pub fn usable(&self, iface: &str) -> bool {
        let member = |s: &str| s.split(',').any(|i| i.trim() == iface);
        if !self.interfaces_use.is_empty() {
            member(&self.interfaces_use)
        } else {
            !member(&self.interfaces_ignore)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selector_masks() {
        let ts = Ts {
            from: Host {
                ip: "10.0.1.3".parse().unwrap(),
                port: 0,
            },
            to: Host {
                ip: "10.0.1.254".parse().unwrap(),
                port: 0,
            },
            proto: 6,
            from_port: 1024,
            to_port: 2047,
        };
        assert_eq!(ts.subnet().0.ip.to_string(), "10.0.1.0");
        assert_eq!(ts.subnet().1, 24);
        assert_eq!(ts.ports(), (1024, 0xfc00));
        let mut single = ts.clone();
        single.to_port = single.from_port;
        assert_eq!(single.ports(), (1024, 0xffff));
        let ipv6 = Ts::from_subnet(
            Host {
                ip: "fd00:1234::".parse().unwrap(),
                port: 0,
            },
            64,
            0,
            0,
            65535,
        )
        .unwrap();
        assert_eq!(ipv6.subnet().1, 64);
    }
}
