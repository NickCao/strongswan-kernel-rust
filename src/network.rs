// SPDX-License-Identifier: GPL-2.0-or-later
// Network semantics ported from kernel_netlink_net.c, Copyright secunet
// Security Networks AG, Martin Willi, Tobias Brunner and contributors.
use crate::{
    error::invalid,
    model::*,
    netlink::{self, Message, Netlink, ACK, CREATE, DUMP, EXCL},
    uapi::{get16, get32, put32},
};
use std::io;

#[derive(Clone, Debug)]
pub struct Link {
    pub index: u32,
    pub name: String,
    pub flags: u32,
    pub mtu: u32,
    pub xfrm: Option<(u32, u32)>,
}
#[derive(Clone, Debug)]
pub struct AddressEntry {
    pub host: Host,
    pub prefix: u8,
    pub scope: u8,
    pub flags: u32,
    pub index: u32,
}
struct Candidate {
    dst: Host,
    prefix: u8,
    gateway: Option<Host>,
    source: Option<Host>,
    index: u32,
    table: u32,
    priority: u32,
    kind: u8,
}
pub struct Network {
    socket: Netlink,
    pub config: Config,
}
fn absent() -> io::Error {
    io::Error::from_raw_os_error(libc::ENOENT)
}
fn text(b: &[u8]) -> io::Result<String> {
    let n = b.iter().position(|b| *b == 0).unwrap_or(b.len());
    std::str::from_utf8(&b[..n])
        .map(str::to_owned)
        .map_err(|_| invalid())
}
pub fn index(name: &str) -> io::Result<u32> {
    if name.is_empty() {
        return Ok(0);
    }
    if name.contains('\0') {
        return Err(invalid());
    }
    let socket = rustix::net::socket_with(
        rustix::net::AddressFamily::INET,
        rustix::net::SocketType::DGRAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )?;
    rustix::net::netdevice::name_to_index(&socket, name).map_err(io::Error::from)
}
impl Network {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            socket: Netlink::new(libc::NETLINK_ROUTE, 0)?,
            config: Config::default(),
        })
    }
    pub fn links(&mut self) -> io::Result<Vec<Link>> {
        let mut links = Vec::new();
        for r in self.socket.request(&Message::new(18, DUMP, vec![0; 16]))? {
            if r.kind != 16 || r.payload.len() < 16 {
                continue;
            }
            let b = &r.payload;
            let mut link = Link {
                index: get32(b, 4),
                flags: get32(b, 8),
                name: String::new(),
                mtu: 0,
                xfrm: None,
            };
            for (kind, value) in netlink::attrs(&b[16..])? {
                match kind {
                    3 => link.name = text(value)?,
                    4 if value.len() == 4 => link.mtu = get32(value, 0),
                    18 => {
                        let nested = netlink::attrs(value)?;
                        if nested
                            .iter()
                            .any(|(k, v)| *k == 1 && v.starts_with(b"xfrm\0"))
                        {
                            let mut if_id = 0;
                            let mut phys = 0;
                            for (_, data) in nested.iter().filter(|(k, _)| *k == 2) {
                                for (k, v) in netlink::attrs(data)? {
                                    if v.len() == 4 {
                                        match k {
                                            1 => phys = get32(v, 0),
                                            2 => if_id = get32(v, 0),
                                            _ => (),
                                        }
                                    }
                                }
                            }
                            link.xfrm = Some((if_id, phys));
                        }
                    }
                    _ => (),
                }
            }
            if !link.name.is_empty() {
                links.push(link);
            }
        }
        Ok(links)
    }
    pub fn addresses(&mut self) -> io::Result<Vec<AddressEntry>> {
        let mut out = Vec::new();
        for r in self.socket.request(&Message::new(22, DUMP, vec![0; 8]))? {
            let b = &r.payload;
            if r.kind != 20 || b.len() < 8 {
                continue;
            }
            if ![libc::AF_INET as u8, libc::AF_INET6 as u8].contains(&b[0]) {
                continue;
            }
            let mut bytes = None;
            let mut local = None;
            let mut flags = b[2] as u32;
            for (kind, value) in netlink::attrs(&b[8..])? {
                match kind {
                    1 => bytes = Some(value),
                    2 => local = Some(value),
                    8 if value.len() == 4 => flags = get32(value, 0),
                    _ => (),
                }
            }
            if let Some(bytes) = local.or(bytes) {
                let host = Host::from_kernel(b[0] as u16, bytes, 0)?;
                out.push(AddressEntry {
                    host,
                    prefix: b[1],
                    scope: b[3],
                    flags,
                    index: get32(b, 4),
                });
            }
        }
        Ok(out)
    }
    pub fn enumerate(&mut self, which: u32) -> io::Result<Vec<Host>> {
        let links = self.links()?;
        let addresses = self.addresses()?;
        Ok(addresses
            .into_iter()
            .filter(|a| {
                let Some(link) = links.iter().find(|l| l.index == a.index) else {
                    return false;
                };
                if link.xfrm.is_some() || a.scope >= 254 || a.flags & (0x08 | 0x20 | 0x40) != 0 {
                    return false;
                }
                let class = if !self.config.usable(&link.name) {
                    4
                } else if link.flags & 1 == 0 {
                    2
                } else {
                    1
                };
                which & class != 0
            })
            .map(|a| a.host)
            .collect())
    }
    pub fn subnets(&mut self) -> io::Result<Vec<(Host, u8, String)>> {
        let links = self.links()?;
        let addresses = self.addresses()?;
        Ok(addresses
            .into_iter()
            .filter_map(|a| {
                let link = links.iter().find(|l| {
                    l.index == a.index && l.flags & 1 != 0 && self.config.usable(&l.name)
                })?;
                if link.xfrm.is_some() || a.scope >= 254 || a.prefix == a.host.bits() {
                    return None;
                }
                Some((network(&a.host, a.prefix), a.prefix, link.name.clone()))
            })
            .collect())
    }
    pub fn interface(&mut self, host: &Host) -> io::Result<String> {
        let addresses = self.addresses()?;
        let links = self.links()?;
        for a in addresses {
            if a.host.ip == host.ip {
                if let Some(link) = links
                    .iter()
                    .find(|l| l.index == a.index && l.flags & 1 != 0 && self.config.usable(&l.name))
                {
                    return Ok(link.name.clone());
                }
            }
        }
        Err(absent())
    }
    fn candidates(&mut self, family: u16) -> io::Result<Vec<Candidate>> {
        let mut query = vec![0; 12];
        query[0] = family as u8;
        let mut out = Vec::new();
        for r in self.socket.request(&Message::new(26, DUMP, query))? {
            let b = &r.payload;
            if r.kind != 24
                || b.len() < 12
                || b[0] as u16 != family
                || b[1] > if family == 2 { 32 } else { 128 }
            {
                continue;
            }
            let mut route = Candidate {
                dst: Host::any(family)?,
                prefix: b[1],
                gateway: None,
                source: None,
                index: 0,
                table: b[4] as u32,
                priority: 0,
                kind: b[7],
            };
            for (kind, v) in netlink::attrs(&b[12..])? {
                match kind {
                    1 => route.dst = Host::from_kernel(family, v, 0)?,
                    4 if v.len() == 4 => route.index = get32(v, 0),
                    5 => route.gateway = Some(Host::from_kernel(family, v, 0)?),
                    6 if v.len() == 4 => route.priority = get32(v, 0),
                    7 => route.source = Some(Host::from_kernel(family, v, 0)?),
                    15 if v.len() == 4 => route.table = get32(v, 0),
                    9 if v.len() >= 8 => {
                        // First live multipath nexthop
                        let mut hops = v;
                        while hops.len() >= 8 {
                            let len = get16(hops, 0) as usize;
                            if len < 8 || len > hops.len() {
                                break;
                            }
                            if hops[2] & 1 == 0 {
                                route.index = get32(hops, 4);
                                for (k, a) in netlink::attrs(&hops[8..len])? {
                                    if k == 5 {
                                        route.gateway = Some(Host::from_kernel(family, a, 0)?);
                                    }
                                }
                                break;
                            }
                            if netlink::align(len) > hops.len() {
                                break;
                            }
                            hops = &hops[netlink::align(len)..];
                        }
                    }
                    _ => (),
                }
            }
            out.push(route);
        }
        out.sort_by_key(|r| (std::cmp::Reverse(r.prefix), r.priority));
        Ok(out)
    }
    pub fn lookup(
        &mut self,
        dest: &Host,
        src: Option<&Host>,
        prefix: i32,
    ) -> io::Result<(Host, Host, String)> {
        if src.is_some_and(|s| s.family() != dest.family()) {
            return Err(invalid());
        }
        let links = self.links()?;
        let addresses = self.addresses()?;
        for r in self.candidates(dest.family())? {
            if ![1, 2].contains(&r.kind)
                || (prefix >= 0 && r.prefix > prefix as u8)
                || network(dest, r.prefix).ip != network(&r.dst, r.prefix).ip
            {
                continue;
            }
            let Some(link) = links.iter().find(|l| {
                l.index == r.index
                    && l.flags & 1 != 0
                    && l.xfrm.is_none()
                    && self.config.usable(&l.name)
            }) else {
                continue;
            };
            let valid = |a: &&AddressEntry| {
                a.host.family() == dest.family() && a.flags & (0x08 | 0x20 | 0x40) == 0
            };
            let source = if let Some(src) = src.filter(|h| !h.ip.is_unspecified()) {
                if !addresses.iter().filter(valid).any(|a| a.host.ip == src.ip) {
                    continue;
                }
                src.clone()
            } else if let Some(h) = r.source {
                h
            } else if let Some(a) = addresses
                .iter()
                .filter(valid)
                .filter(|a| a.index == r.index && a.scope < 254)
                .min_by_key(|a| {
                    if network(dest, a.prefix).ip == network(&a.host, a.prefix).ip {
                        0
                    } else {
                        1
                    }
                })
            {
                a.host.clone()
            } else {
                continue;
            };
            return Ok((
                source,
                r.gateway.unwrap_or(Host::any(dest.family())?),
                link.name.clone(),
            ));
        }
        Err(io::Error::from_raw_os_error(libc::ENETUNREACH))
    }
    pub fn create_xfrmi(
        &mut self,
        name: String,
        if_id: u32,
        phys: String,
        mtu: u32,
    ) -> io::Result<()> {
        if name.is_empty() || name.len() >= libc::IFNAMSIZ {
            return Err(invalid());
        }
        let mut b = vec![0; 16];
        put32(&mut b, 8, 1);
        put32(&mut b, 12, 1);
        let mut m = Message::new(16, ACK | CREATE | EXCL, b);
        m.attr(3, &nul(&name))?;
        if mtu != 0 {
            m.attr32(4, mtu)?;
        }
        let mut info = Message::new(0, 0, vec![]);
        info.attr(1, b"xfrm\0")?;
        let mut data = Message::new(0, 0, vec![]);
        data.attr32(2, if_id)?;
        if !phys.is_empty() {
            data.attr32(1, index(&phys)?)?;
        }
        info.attr(2 | 0x8000, &data.payload)?;
        m.attr(18 | 0x8000, &info.payload)?;
        self.socket.ack(&m)?;
        Ok(())
    }
    pub(crate) fn delete_xfrmi(&mut self, index: u32) -> io::Result<()> {
        let mut b = vec![0; 16];
        put32(&mut b, 4, index);
        self.socket.ack(&Message::new(17, ACK, b))?;
        Ok(())
    }
}
fn nul(s: &str) -> Vec<u8> {
    let mut b = s.as_bytes().to_vec();
    b.push(0);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_network_discovery() {
        let mut net = Network::new().unwrap();
        let links = net.links().unwrap();
        assert!(links.iter().any(|l| l.name == "lo"));
        let addresses = net.addresses().unwrap();
        assert!(addresses.iter().any(|a| a.host.ip.is_loopback()));
        assert_eq!(
            net.interface(&Host {
                ip: "127.0.0.1".parse().unwrap(),
                port: 0
            })
            .unwrap(),
            "lo"
        );
    }
}
