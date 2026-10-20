// SPDX-License-Identifier: GPL-2.0-or-later
// Network semantics ported from kernel_netlink_net.c, Copyright secunet
// Security Networks AG, Martin Willi, Tobias Brunner and contributors.
use super::netlink::{Message, Netlink, NlFamily, NlmF};
use crate::{error::invalid, model::*};
use netlink_packet_core::ParseableParametrized;
use netlink_packet_route::{
    address::{AddressAttribute, AddressFlags, AddressMessage, AddressScope},
    link::{InfoData, InfoKind, InfoXfrm, LinkAttribute, LinkFlags, LinkInfo, LinkMessage},
    route::{RouteAddress, RouteAttribute, RouteMessage, RouteType},
    AddressFamily, RouteNetlinkMessage,
};
use std::{io, sync::Arc};

// kernel_address_type_t: DOWN and IGNORED permit additional interfaces;
// REGULAR still selects their non-virtual addresses.
const ADDR_TYPE_REGULAR: u32 = 1 << 0;
const ADDR_TYPE_DOWN: u32 = 1 << 1;
const ADDR_TYPE_IGNORED: u32 = 1 << 2;

#[derive(Clone, Debug)]
pub struct Link {
    pub index: u32,
    pub name: String,
    pub flags: LinkFlags,
    pub mtu: u32,
    pub master: u32,
    pub group: u32,
    pub xfrm: Option<(u32, u32)>,
}
impl Link {
    fn from_message(info: LinkMessage) -> Self {
        let mut link = Self {
            index: info.header.index,
            flags: info.header.flags,
            name: String::new(),
            mtu: 0,
            master: 0,
            group: 0,
            xfrm: None,
        };
        for attr in info.attributes {
            match attr {
                LinkAttribute::IfName(name) => link.name = name,
                LinkAttribute::Mtu(mtu) => link.mtu = mtu,
                LinkAttribute::Controller(master) => link.master = master,
                LinkAttribute::Group(group) => link.group = group,
                LinkAttribute::LinkInfo(infos) => {
                    for info in infos {
                        match info {
                            LinkInfo::Kind(InfoKind::Xfrm) => {
                                link.xfrm.get_or_insert((0, 0));
                            }
                            LinkInfo::Data(InfoData::Xfrm(attrs)) => {
                                let (if_id, phys) = link.xfrm.get_or_insert((0, 0));
                                for attr in attrs {
                                    match attr {
                                        InfoXfrm::IfId(value) => *if_id = value,
                                        InfoXfrm::Link(value) => *phys = value,
                                        _ => (),
                                    }
                                }
                            }
                            _ => (),
                        }
                    }
                }
                _ => (),
            }
        }
        link
    }
}
#[derive(Clone, Debug)]
pub struct AddressEntry {
    pub host: Host,
    pub prefix: u8,
    pub scope: u8,
    pub flags: AddressFlags,
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
fn route_host(address: RouteAddress) -> io::Result<Host> {
    let ip = match address {
        RouteAddress::Inet(ip) => ip.into(),
        RouteAddress::Inet6(ip) => ip.into(),
        _ => return Err(invalid()),
    };
    Ok(Host { ip, port: 0 })
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
    pub(crate) fn request(
        &self,
        request: RouteNetlinkMessage,
        flags: NlmF,
    ) -> io::Result<Vec<RouteNetlinkMessage>> {
        self.socket
            .request(&Message::new(request.message_type(), flags, &request))?
            .into_iter()
            .map(|reply| {
                RouteNetlinkMessage::parse_with_param(&reply.payload, reply.kind)
                    .map_err(io::Error::other)
            })
            .collect()
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
        let request = RouteNetlinkMessage::GetLink(LinkMessage::default());
        for reply in self.request(request, NlmF::DUMP)? {
            let RouteNetlinkMessage::NewLink(info) = reply else {
                continue;
            };
            let link = Link::from_message(info);
            if !link.name.is_empty() {
                links.push(link);
            }
        }
        Ok(links)
    }
    pub(crate) fn link(&mut self, index: u32) -> io::Result<Option<Link>> {
        let mut request = LinkMessage::default();
        request.header.index = index;
        let replies = match self.request(RouteNetlinkMessage::GetLink(request), NlmF::empty()) {
            Ok(replies) => replies,
            Err(error) if error.raw_os_error() == Some(libc::ENODEV) => return Ok(None),
            Err(error) => return Err(error),
        };
        Ok(replies.into_iter().find_map(|reply| match reply {
            RouteNetlinkMessage::NewLink(info) => Some(Link::from_message(info)),
            _ => None,
        }))
    }
    pub fn addresses(&mut self) -> io::Result<Vec<AddressEntry>> {
        let mut out = Vec::new();
        let request = RouteNetlinkMessage::GetAddress(AddressMessage::default());
        for reply in self.request(request, NlmF::DUMP)? {
            let RouteNetlinkMessage::NewAddress(info) = reply else {
                continue;
            };
            if !matches!(
                info.header.family,
                AddressFamily::Inet | AddressFamily::Inet6
            ) {
                continue;
            }
            let mut address = None;
            let mut local = None;
            let mut flags = AddressFlags::from_bits_retain(info.header.flags.bits().into());
            for attr in info.attributes {
                match attr {
                    AddressAttribute::Address(ip) => address = Some(ip),
                    AddressAttribute::Local(ip) => local = Some(ip),
                    AddressAttribute::Flags(value) => flags = value,
                    _ => (),
                }
            }
            if let Some(ip) = local.or(address) {
                out.push(AddressEntry {
                    host: Host { ip, port: 0 },
                    prefix: info.header.prefix_len,
                    scope: info.header.scope.into(),
                    flags,
                    index: info.header.index,
                });
            }
        }
        Ok(out)
    }
    pub fn enumerate(&mut self, which: u32) -> io::Result<Vec<Host>> {
        if which & ADDR_TYPE_REGULAR == 0 {
            return Ok(Vec::new());
        }
        let snapshot = self.snapshot()?;
        Ok(snapshot
            .addresses
            .iter()
            .filter(|a| {
                let Some(link) = snapshot.links.iter().find(|l| l.index == a.index) else {
                    return false;
                };
                if link.xfrm.is_some()
                    || a.scope >= u8::from(AddressScope::Link)
                    || a.host.ip.is_loopback()
                    || a.host.is_link_local()
                    || a.flags.intersects(
                        AddressFlags::Dadfailed
                            | AddressFlags::Deprecated
                            | AddressFlags::Tentative,
                    )
                {
                    return false;
                }
                (self.config.usable(&link.name) || which & ADDR_TYPE_IGNORED != 0)
                    && (link.flags.contains(LinkFlags::Up) || which & ADDR_TYPE_DOWN != 0)
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
                    l.index == a.index
                        && l.flags.contains(LinkFlags::Up)
                        && self.config.usable(&l.name)
                })?;
                if link.xfrm.is_some()
                    || a.scope >= u8::from(AddressScope::Host)
                    || a.prefix == a.host.bits()
                {
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
                    .find(|l| l.index == a.index && self.usable_link(l))
                {
                    return Ok(link.name.clone());
                }
            }
        }
        Err(absent())
    }
    fn usable_link(&self, link: &Link) -> bool {
        link.flags.contains(LinkFlags::Up) && link.xfrm.is_none() && self.config.usable(&link.name)
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
        let mut query = RouteMessage::default();
        query.header.address_family = dest.ip.into();
        query.header.destination_prefix_length = dest.bits();
        query.header.source_prefix_length = if src.is_some() { dest.bits() } else { 0 };
        query
            .attributes
            .push(RouteAttribute::Destination(dest.ip.into()));
        if let Some(src) = src {
            query.attributes.push(RouteAttribute::Source(src.ip.into()));
        }
        // Use the kernel's FIB and routing rules, without dumping BGP tables
        // or trying to choose an alternative to an excluded kernel route.
        let info = self
            .request(RouteNetlinkMessage::GetRoute(query), NlmF::empty())?
            .into_iter()
            .find_map(|reply| match reply {
                RouteNetlinkMessage::NewRoute(info) => Some(info),
                _ => None,
            })
            .ok_or_else(absent)?;
        let unreachable = || io::Error::from_raw_os_error(libc::ENETUNREACH);
        if !matches!(info.header.kind, RouteType::Unicast | RouteType::Local) {
            return Err(unreachable());
        }
        let (mut index, mut gateway, mut source) = (0, None, None);
        for attr in info.attributes {
            match attr {
                RouteAttribute::Oif(value) => index = value,
                RouteAttribute::Gateway(value) => gateway = Some(route_host(value)?),
                RouteAttribute::PrefSource(value) => source = Some(route_host(value)?),
                _ => (),
            }
        }
        let snapshot = self.snapshot()?;
        let link = snapshot
            .links
            .iter()
            .find(|l| l.index == index && self.usable_link(l))
            .ok_or_else(unreachable)?;
        // A caller-supplied or FIB-selected source may belong to another
        // interface, including one excluded from address discovery. Trust
        // the successful route lookup instead of filtering its owner again.
        let source = if let Some(source) = src.or(source.as_ref()) {
            source.clone()
        } else {
            snapshot
                .addresses
                .iter()
                .find(|a| {
                    a.index == index
                        && a.host.family() == family
                        && !a.flags.intersects(
                            AddressFlags::Dadfailed
                                | AddressFlags::Deprecated
                                | AddressFlags::Tentative,
                        )
                        && a.scope < u8::from(AddressScope::Link)
                        && !a.host.ip.is_loopback()
                        && !a.host.is_link_local()
                })
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
