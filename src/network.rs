// SPDX-License-Identifier: GPL-2.0-or-later
// Network semantics ported from kernel_netlink_net.c, Copyright secunet
// Security Networks AG, Martin Willi, Tobias Brunner and contributors.
use crate::{
    error::invalid,
    model::*,
    netlink::{self, attribute, get32, Netlink, NlFamily, NlmF},
};
use neli::{
    consts::rtnl::{
        Ifa, Iff, Ifla, IflaInfo, RtAddrFamily, RtScope, RtTable, Rta, Rtm, Rtn, Rtprot,
    },
    rtnl::{Ifaddrmsg, Ifinfomsg, IfinfomsgBuilder, RtgenmsgBuilder, Rtmsg, RtmsgBuilder},
    types::RtBuffer,
    FromBytesWithInput,
};
use std::{
    io::{self, Cursor},
    sync::Arc,
};

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
struct Snapshot {
    links: Vec<Link>,
    addresses: Vec<AddressEntry>,
}
pub struct Network {
    socket: Netlink,
    pub config: Config,
    snapshot: Option<Arc<Snapshot>>,
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
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::DGRAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )?;
    rustix::net::netdevice::name_to_index(&socket, name).map_err(io::Error::from)
}
impl Network {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            socket: Netlink::new(NlFamily::Route)?,
            config: Config::default(),
            snapshot: None,
        })
    }
    pub fn invalidate(&mut self) {
        self.snapshot = None;
    }
    fn snapshot(&mut self) -> io::Result<Arc<Snapshot>> {
        if self.snapshot.is_none() {
            self.snapshot = Some(Arc::new(Snapshot {
                links: self.links()?,
                addresses: self.addresses()?,
            }));
        }
        Ok(self.snapshot.as_ref().unwrap().clone())
    }
    pub fn links(&mut self) -> io::Result<Vec<Link>> {
        let mut links = Vec::new();
        let request = IfinfomsgBuilder::default()
            .ifi_family(RtAddrFamily::Unspecified)
            .build()
            .map_err(io::Error::other)?;
        for r in self
            .socket
            .request_payload(Rtm::Getlink.into(), NlmF::DUMP, request)?
        {
            if r.kind != u16::from(Rtm::Newlink) {
                continue;
            }
            let info =
                Ifinfomsg::from_bytes_with_input(&mut Cursor::new(&r.payload), r.payload.len())
                    .map_err(io::Error::other)?;
            let mut link = Link {
                index: *info.ifi_index() as u32,
                flags: info.ifi_flags().bits(),
                name: String::new(),
                mtu: 0,
                xfrm: None,
            };
            for attr in info.rtattrs().iter() {
                let value = attr.rta_payload().as_ref();
                match Ifla::from(u16::from(*attr.rta_type()) & 0x3fff) {
                    Ifla::Ifname => link.name = text(value)?,
                    Ifla::Mtu if value.len() == 4 => link.mtu = get32(value, 0),
                    Ifla::Linkinfo => {
                        let nested = netlink::attrs(value)?;
                        if nested
                            .iter()
                            .any(|(k, v)| k == 1 && v.starts_with(b"xfrm\0"))
                        {
                            let mut if_id = 0;
                            let mut phys = 0;
                            for (_, data) in nested.iter().filter(|(k, _)| *k == 2) {
                                for (k, v) in netlink::attrs(data)?.iter() {
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
        let request = RtgenmsgBuilder::default()
            .rtgen_family(RtAddrFamily::Unspecified)
            .build()
            .map_err(io::Error::other)?;
        for r in self
            .socket
            .request_payload(Rtm::Getaddr.into(), NlmF::DUMP, request)?
        {
            if r.kind != u16::from(Rtm::Newaddr) {
                continue;
            }
            let info =
                Ifaddrmsg::from_bytes_with_input(&mut Cursor::new(&r.payload), r.payload.len())
                    .map_err(io::Error::other)?;
            let family = u8::from(*info.ifa_family());
            if ![libc::AF_INET as u8, libc::AF_INET6 as u8].contains(&family) {
                continue;
            }
            let mut bytes = None;
            let mut local = None;
            let mut flags = info.ifa_flags().bits() as u32;
            for attr in info.rtattrs().iter() {
                let value = attr.rta_payload().as_ref();
                match attr.rta_type() {
                    Ifa::Address => bytes = Some(value),
                    Ifa::Local => local = Some(value),
                    Ifa::Flags if value.len() == 4 => flags = get32(value, 0),
                    _ => (),
                }
            }
            if let Some(bytes) = local.or(bytes) {
                let host = Host::from_kernel(family.into(), bytes, 0)?;
                out.push(AddressEntry {
                    host,
                    prefix: *info.ifa_prefixlen(),
                    scope: u8::from(*info.ifa_scope()),
                    flags,
                    index: *info.ifa_index(),
                });
            }
        }
        Ok(out)
    }
    pub fn enumerate(&mut self, which: u32) -> io::Result<Vec<Host>> {
        let snapshot = self.snapshot()?;
        Ok(snapshot
            .addresses
            .iter()
            .filter(|a| {
                let Some(link) = snapshot.links.iter().find(|l| l.index == a.index) else {
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
            .map(|a| a.host.clone())
            .collect())
    }
    pub fn subnets(&mut self) -> io::Result<Vec<(Host, u8, String)>> {
        let snapshot = self.snapshot()?;
        Ok(snapshot
            .addresses
            .iter()
            .filter_map(|a| {
                let link = snapshot.links.iter().find(|l| {
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
        let snapshot = self.snapshot()?;
        for a in &snapshot.addresses {
            if a.host.ip == host.ip {
                if let Some(link) = snapshot
                    .links
                    .iter()
                    .find(|l| l.index == a.index && l.flags & 1 != 0 && self.config.usable(&l.name))
                {
                    return Ok(link.name.clone());
                }
            }
        }
        Err(absent())
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
        // ranet only needs host lookups. Subnet nexthops are used for route
        // installation, which belongs to the network configuration instead.
        if prefix != -1 && prefix != i32::from(dest.bits()) {
            return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
        }
        let src = src.filter(|s| !s.ip.is_unspecified());
        let family = dest.family();
        let mut attributes = RtBuffer::new();
        attributes.push(attribute(Rta::Dst, dest.bytes().as_slice())?);
        if let Some(src) = src {
            attributes.push(attribute(Rta::Src, src.bytes().as_slice())?);
        }
        let query = RtmsgBuilder::default()
            .rtm_family(RtAddrFamily::from(family as u8))
            .rtm_dst_len(dest.bits())
            .rtm_src_len(if src.is_some() { dest.bits() } else { 0 })
            .rtm_tos(0)
            .rtm_table(RtTable::Unspec)
            .rtm_protocol(Rtprot::Unspec)
            .rtm_scope(RtScope::Universe)
            .rtm_type(Rtn::Unspec)
            .rtattrs(attributes)
            .build()
            .map_err(io::Error::other)?;
        // Use the kernel's FIB and routing rules, without dumping BGP tables
        // or trying to choose an alternative to an excluded kernel route.
        let r = self
            .socket
            .request_payload(Rtm::Getroute.into(), NlmF::empty(), query)?
            .into_iter()
            .find(|r| r.kind == u16::from(Rtm::Newroute))
            .ok_or_else(absent)?;
        let info = Rtmsg::from_bytes_with_input(&mut Cursor::new(&r.payload), r.payload.len())
            .map_err(io::Error::other)?;
        let unreachable = || io::Error::from_raw_os_error(libc::ENETUNREACH);
        if !matches!(*info.rtm_type(), Rtn::Unicast | Rtn::Local) {
            return Err(unreachable());
        }
        let (mut index, mut gateway, mut source) = (0, None, None);
        for attr in info.rtattrs().iter() {
            let value = attr.rta_payload().as_ref();
            match attr.rta_type() {
                Rta::Oif if value.len() == 4 => index = get32(value, 0),
                Rta::Gateway => gateway = Some(Host::from_kernel(family, value, 0)?),
                Rta::Prefsrc => source = Some(Host::from_kernel(family, value, 0)?),
                _ => (),
            }
        }
        let snapshot = self.snapshot()?;
        let link = snapshot
            .links
            .iter()
            .find(|l| {
                l.index == index
                    && l.flags & 1 != 0
                    && l.xfrm.is_none()
                    && self.config.usable(&l.name)
            })
            .ok_or_else(unreachable)?;
        let valid =
            |a: &&AddressEntry| a.host.family() == family && a.flags & (0x08 | 0x20 | 0x40) == 0;
        let source = if let Some(src) = src {
            if !snapshot
                .addresses
                .iter()
                .filter(valid)
                .any(|a| a.host.ip == src.ip)
            {
                return Err(unreachable());
            }
            src.clone()
        } else if let Some(source) = source {
            source
        } else {
            snapshot
                .addresses
                .iter()
                .filter(valid)
                .find(|a| a.index == index && a.scope < 254)
                .ok_or_else(unreachable)?
                .host
                .clone()
        };
        Ok((
            source,
            gateway.unwrap_or(Host::any(family)?),
            link.name.clone(),
        ))
    }
    pub fn create_xfrmi(
        &mut self,
        name: String,
        if_id: u32,
        phys: String,
        master: String,
        mtu: u32,
    ) -> io::Result<()> {
        if name.is_empty() || name.len() >= libc::IFNAMSIZ {
            return Err(invalid());
        }
        let mut attributes = RtBuffer::new();
        attributes.push(attribute(Ifla::Ifname, name.as_str())?);
        if mtu != 0 {
            attributes.push(attribute(Ifla::Mtu, mtu)?);
        }
        if !master.is_empty() {
            attributes.push(attribute(Ifla::Master, index(&master)?)?);
        }
        let mut data = RtBuffer::new();
        data.push(attribute(2u16, if_id)?);
        if !phys.is_empty() {
            data.push(attribute(1u16, index(&phys)?)?);
        }
        let info: RtBuffer<_, _> = [
            attribute(u16::from(IflaInfo::Kind), "xfrm")?,
            attribute(u16::from(IflaInfo::Data) | 0x8000, data)?,
        ]
        .into_iter()
        .collect();
        attributes.push(attribute(
            Ifla::from(u16::from(Ifla::Linkinfo) | 0x8000),
            info,
        )?);
        let flags = Iff::UP | Iff::MULTICAST;
        let payload = IfinfomsgBuilder::default()
            .ifi_family(RtAddrFamily::Unspecified)
            .ifi_flags(flags)
            .ifi_change(flags)
            .rtattrs(attributes)
            .build()
            .map_err(io::Error::other)?;
        self.socket.request_payload(
            Rtm::Newlink.into(),
            NlmF::ACK | NlmF::CREATE | NlmF::EXCL,
            payload,
        )?;
        self.invalidate();
        Ok(())
    }
    pub(crate) fn delete_xfrmi(&mut self, index: u32) -> io::Result<()> {
        let payload = IfinfomsgBuilder::default()
            .ifi_family(RtAddrFamily::Unspecified)
            .ifi_index(index as i32)
            .build()
            .map_err(io::Error::other)?;
        self.socket
            .request_payload(Rtm::Dellink.into(), NlmF::ACK, payload)?;
        self.invalidate();
        Ok(())
    }
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
