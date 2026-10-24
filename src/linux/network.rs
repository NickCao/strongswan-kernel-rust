// SPDX-License-Identifier: GPL-2.0-or-later
// Network semantics ported from kernel_netlink_net.c, Copyright secunet
// Security Networks AG, Martin Willi, Tobias Brunner and contributors.
use super::netlink::{Message, Netlink, NlFamily, NlmF, Reply};
use crate::{error::invalid, model::*, rpc_api::AddressTypes};
use netlink_packet_core::{
    parse_string, parse_u32, Emitable, Nla, NlasIterator, ParseableParametrized,
};
use netlink_packet_route::{
    address::{AddressAttribute, AddressFlags, AddressMessage, AddressScope},
    link::{InfoXfrm, LinkAttribute, LinkFlags, LinkHeader, LinkMessage},
    route::{RouteAddress, RouteAttribute, RouteMessage, RouteType},
    AddressFamily, RouteNetlinkMessage,
};
use std::{io, sync::Arc};

#[derive(Clone, Debug)]
pub struct Link {
    pub index: u32,
    pub name: String,
    pub flags: LinkFlags,
    pub mtu: u32,
    pub master: u32,
    pub group: u32,
    pub xfrm_if_id: Option<u32>,
}
impl Link {
    fn parse(payload: &[u8]) -> io::Result<Self> {
        let header = LinkHeader::parse(payload).map_err(io::Error::other)?;
        let mut link = Self {
            index: header.index,
            flags: header.flags,
            name: String::new(),
            mtu: 0,
            master: 0,
            group: 0,
            xfrm_if_id: None,
        };
        // Walk attribute framing, decoding only the fields consumed by this
        // daemon. AF_SPEC, statistics, VF data and other kinds' nested settings
        // can dwarf these fields on production hosts.
        for attr in NlasIterator::new(&payload[header.buffer_len()..]) {
            let attr = attr.map_err(io::Error::other)?;
            match attr.kind() {
                libc::IFLA_IFNAME => {
                    link.name = parse_string(attr.value()).map_err(io::Error::other)?
                }
                libc::IFLA_MTU => link.mtu = parse_u32(attr.value()).map_err(io::Error::other)?,
                libc::IFLA_MASTER => {
                    link.master = parse_u32(attr.value()).map_err(io::Error::other)?
                }
                libc::IFLA_GROUP => {
                    link.group = parse_u32(attr.value()).map_err(io::Error::other)?
                }
                libc::IFLA_LINKINFO => link.xfrm_if_id = Self::xfrm_id(attr.value())?,
                _ => (),
            }
        }
        Ok(link)
    }

    fn xfrm_id(payload: &[u8]) -> io::Result<Option<u32>> {
        let mut xfrm = false;
        let mut data = None;
        for attr in NlasIterator::new(payload) {
            let attr = attr.map_err(io::Error::other)?;
            match attr.kind() {
                libc::IFLA_INFO_KIND => {
                    let value = attr.value();
                    xfrm = value.strip_suffix(&[0]).unwrap_or(value) == b"xfrm";
                }
                libc::IFLA_INFO_DATA => data = Some(attr),
                _ => (),
            }
        }
        if !xfrm {
            return Ok(None);
        }
        let mut id = 0;
        if let Some(data) = data {
            for attr in NlasIterator::new(data.value()) {
                let attr = attr.map_err(io::Error::other)?;
                if attr.kind() == InfoXfrm::IfId(0).kind() {
                    id = parse_u32(attr.value()).map_err(io::Error::other)?;
                }
            }
        }
        Ok(Some(id))
    }
}
#[derive(Clone, Debug)]
pub struct AddressEntry {
    pub host: Endpoint,
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
    pub config: SessionConfig,
    snapshot: Option<Arc<Snapshot>>,
}
fn absent() -> io::Error {
    io::Error::from_raw_os_error(libc::ENOENT)
}
fn route_host(address: RouteAddress) -> io::Result<Endpoint> {
    let ip = match address {
        RouteAddress::Inet(ip) => ip.into(),
        RouteAddress::Inet6(ip) => ip.into(),
        _ => return Err(invalid()),
    };
    Ok(Endpoint::new(ip, 0))
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
    pub async fn new() -> io::Result<Self> {
        Ok(Self {
            socket: Netlink::new(NlFamily::Route).await?,
            config: SessionConfig::default(),
            snapshot: None,
        })
    }
    pub(crate) async fn request(
        &self,
        request: RouteNetlinkMessage,
        flags: NlmF,
    ) -> io::Result<Vec<RouteNetlinkMessage>> {
        self.request_raw(request, flags)
            .await?
            .into_iter()
            .map(|reply| {
                RouteNetlinkMessage::parse_with_param(&reply.payload, reply.kind)
                    .map_err(io::Error::other)
            })
            .collect()
    }
    async fn request_raw(
        &self,
        request: RouteNetlinkMessage,
        flags: NlmF,
    ) -> io::Result<Vec<Reply>> {
        self.socket
            .request(&Message::new(request.message_type(), flags, &request))
            .await
    }
    pub fn invalidate(&mut self) {
        self.snapshot = None;
    }
    async fn snapshot(&mut self) -> io::Result<Arc<Snapshot>> {
        if self.snapshot.is_none() {
            self.snapshot = Some(Arc::new(Snapshot {
                links: self.links().await?,
                addresses: self.addresses().await?,
            }));
        }
        Ok(self.snapshot.as_ref().unwrap().clone())
    }
    pub async fn links(&mut self) -> io::Result<Vec<Link>> {
        let mut links = Vec::new();
        let request = RouteNetlinkMessage::GetLink(LinkMessage::default());
        for reply in self.request_raw(request, NlmF::DUMP).await? {
            if reply.kind != libc::RTM_NEWLINK {
                continue;
            }
            let link = Link::parse(&reply.payload)?;
            if !link.name.is_empty() {
                links.push(link);
            }
        }
        Ok(links)
    }
    pub(crate) async fn link(&mut self, index: u32) -> io::Result<Option<Link>> {
        let mut request = LinkMessage::default();
        request.header.index = index;
        self.get_link(request).await
    }
    pub(crate) async fn link_by_name(&mut self, name: &str) -> io::Result<Option<Link>> {
        let mut request = LinkMessage::default();
        request
            .attributes
            .push(LinkAttribute::IfName(name.to_owned()));
        self.get_link(request).await
    }
    async fn get_link(&self, request: LinkMessage) -> io::Result<Option<Link>> {
        let replies = match self
            .request_raw(RouteNetlinkMessage::GetLink(request), NlmF::empty())
            .await
        {
            Ok(replies) => replies,
            Err(error) if error.raw_os_error() == Some(libc::ENODEV) => return Ok(None),
            Err(error) => return Err(error),
        };
        replies
            .into_iter()
            .find(|reply| reply.kind == libc::RTM_NEWLINK)
            .map(|reply| Link::parse(&reply.payload))
            .transpose()
    }
    pub async fn addresses(&mut self) -> io::Result<Vec<AddressEntry>> {
        let mut out = Vec::new();
        let request = RouteNetlinkMessage::GetAddress(AddressMessage::default());
        for reply in self.request(request, NlmF::DUMP).await? {
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
                    host: Endpoint::new(ip, 0),
                    prefix: info.header.prefix_len,
                    scope: info.header.scope.into(),
                    flags,
                    index: info.header.index,
                });
            }
        }
        Ok(out)
    }
    pub async fn enumerate(&mut self, which: AddressTypes) -> io::Result<Vec<Endpoint>> {
        if !which.contains(AddressTypes::REGULAR) {
            return Ok(Vec::new());
        }
        let snapshot = self.snapshot().await?;
        Ok(snapshot
            .addresses
            .iter()
            .filter(|a| {
                let Some(link) = snapshot.links.iter().find(|l| l.index == a.index) else {
                    return false;
                };
                if link.xfrm_if_id.is_some()
                    || a.scope >= u8::from(AddressScope::Link)
                    || a.host.address.is_loopback()
                    || a.host.is_link_local()
                    || a.flags.intersects(
                        AddressFlags::Dadfailed
                            | AddressFlags::Deprecated
                            | AddressFlags::Tentative,
                    )
                {
                    return false;
                }
                (self.config.usable(&link.name) || which.contains(AddressTypes::IGNORED))
                    && (link.flags.contains(LinkFlags::Up) || which.contains(AddressTypes::DOWN))
            })
            .map(|a| a.host)
            .collect())
    }
    pub async fn subnets(&mut self) -> io::Result<Vec<(Endpoint, u8, String)>> {
        let snapshot = self.snapshot().await?;
        Ok(snapshot
            .addresses
            .iter()
            .filter_map(|a| {
                let link = snapshot.links.iter().find(|l| {
                    l.index == a.index
                        && l.flags.contains(LinkFlags::Up)
                        && self.config.usable(&l.name)
                })?;
                if link.xfrm_if_id.is_some()
                    || a.scope >= u8::from(AddressScope::Host)
                    || a.prefix == a.host.bits()
                {
                    return None;
                }
                Some((network(&a.host, a.prefix), a.prefix, link.name.clone()))
            })
            .collect())
    }
    pub async fn interface(&mut self, host: &Endpoint) -> io::Result<String> {
        let snapshot = self.snapshot().await?;
        for a in &snapshot.addresses {
            if a.host.address == host.address {
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
        link.flags.contains(LinkFlags::Up)
            && link.xfrm_if_id.is_none()
            && self.config.usable(&link.name)
    }
    pub async fn lookup(
        &mut self,
        dest: &Endpoint,
        src: Option<&Endpoint>,
        prefix: i32,
    ) -> io::Result<(Endpoint, Endpoint, String)> {
        if src.is_some_and(|s| s.family() != dest.family()) {
            return Err(invalid());
        }
        // ranet only needs host lookups. Subnet nexthops are used for route
        // installation, which belongs to the network configuration instead.
        if prefix != -1 && prefix != i32::from(dest.bits()) {
            return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
        }
        let src = src.filter(|s| !s.address.is_unspecified());
        let family = dest.family();
        let mut query = RouteMessage::default();
        query.header.address_family = dest.address.into();
        query.header.destination_prefix_length = dest.bits();
        query.header.source_prefix_length = if src.is_some() { dest.bits() } else { 0 };
        query
            .attributes
            .push(RouteAttribute::Destination(dest.address.into()));
        if let Some(src) = src {
            query
                .attributes
                .push(RouteAttribute::Source(src.address.into()));
        }
        // Use the kernel's FIB and routing rules, without dumping BGP tables
        // or trying to choose an alternative to an excluded kernel route.
        let info = self
            .request(RouteNetlinkMessage::GetRoute(query), NlmF::empty())
            .await?
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
        let snapshot = self.snapshot().await?;
        let link = snapshot
            .links
            .iter()
            .find(|l| l.index == index && self.usable_link(l))
            .ok_or_else(unreachable)?;
        // A caller-supplied or FIB-selected source may belong to another
        // interface, including one excluded from address discovery. Trust
        // the successful route lookup instead of filtering its owner again.
        let source = if let Some(source) = src.or(source.as_ref()) {
            *source
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
                        && !a.host.address.is_loopback()
                        && !a.host.is_link_local()
                })
                .ok_or_else(unreachable)?
                .host
        };
        Ok((
            source,
            gateway.unwrap_or(Endpoint::any(family)?),
            link.name.clone(),
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::{DefaultNla, Parseable, NLA_F_NESTED};
    use netlink_packet_route::link::{InfoData, InfoKind, LinkInfo};

    fn link_payload(attributes: Vec<LinkAttribute>) -> Vec<u8> {
        let mut message = LinkMessage::default();
        message.header.index = 7;
        message.header.flags = LinkFlags::Up | LinkFlags::Multicast;
        message.attributes = attributes;
        let mut payload = vec![0; message.buffer_len()];
        message.emit(&mut payload);
        payload
    }

    #[test]
    fn link_parsing_decodes_needed_fields_and_skips_unmanaged_payloads() {
        let payload = link_payload(vec![
            LinkAttribute::IfName("ranet00000029".into()),
            LinkAttribute::Mtu(1400),
            LinkAttribute::Controller(3),
            LinkAttribute::Group(17227),
            LinkAttribute::LinkInfo(vec![
                LinkInfo::Kind(InfoKind::Xfrm),
                LinkInfo::Data(InfoData::Xfrm(vec![InfoXfrm::IfId(41)])),
                LinkInfo::Other(DefaultNla::new(libc::IFLA_INFO_XSTATS, vec![0xff])),
            ]),
            // Valid framing with deliberately invalid unused payloads proves
            // that statistics and deeply nested address-family data are skipped.
            LinkAttribute::Other(DefaultNla::new(libc::IFLA_STATS64, vec![0xff])),
            LinkAttribute::Other(DefaultNla::new(
                libc::IFLA_AF_SPEC | NLA_F_NESTED,
                vec![0xff],
            )),
        ]);
        assert!(LinkMessage::parse(payload.as_slice()).is_err());
        let link = Link::parse(&payload).unwrap();
        assert_eq!(link.index, 7);
        assert_eq!(link.flags, LinkFlags::Up | LinkFlags::Multicast);
        assert_eq!(link.name, "ranet00000029");
        assert_eq!(
            (link.mtu, link.master, link.group, link.xfrm_if_id),
            (1400, 3, 17227, Some(41))
        );
    }

    #[test]
    fn link_parsing_skips_other_device_kinds_data() {
        for kind in [InfoKind::Veth, InfoKind::Bridge, InfoKind::Vrf] {
            let payload = link_payload(vec![LinkAttribute::LinkInfo(vec![
                LinkInfo::Kind(kind),
                LinkInfo::Other(DefaultNla::new(libc::IFLA_INFO_DATA, vec![0xff])),
            ])]);
            assert_eq!(Link::parse(&payload).unwrap().xfrm_if_id, None);
        }
        let payload = link_payload(vec![LinkAttribute::LinkInfo(vec![LinkInfo::Kind(
            InfoKind::Xfrm,
        )])]);
        assert_eq!(Link::parse(&payload).unwrap().xfrm_if_id, Some(0));
    }

    #[test]
    fn link_parsing_rejects_invalid_needed_fields_and_framing() {
        assert!(Link::parse(&[0; 15]).is_err());
        let mut payload = link_payload(Vec::new());
        payload.extend_from_slice(&[1, 0]);
        assert!(Link::parse(&payload).is_err());
        for kind in [libc::IFLA_MTU, libc::IFLA_MASTER, libc::IFLA_GROUP] {
            let payload = link_payload(vec![LinkAttribute::Other(DefaultNla::new(kind, vec![1]))]);
            assert!(Link::parse(&payload).is_err());
        }
        let payload = link_payload(vec![LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Xfrm),
            LinkInfo::Data(InfoData::Xfrm(vec![InfoXfrm::Other(DefaultNla::new(
                InfoXfrm::IfId(0).kind(),
                vec![1],
            ))])),
        ])]);
        assert!(Link::parse(&payload).is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn actual_network_discovery() {
        let mut net = Network::new().await.unwrap();
        let links = net.links().await.unwrap();
        assert!(links.iter().any(|l| l.name == "lo"));
        let addresses = net.addresses().await.unwrap();
        assert!(addresses.iter().any(|a| a.host.address.is_loopback()));
        assert_eq!(
            net.interface(&Endpoint::new("127.0.0.1".parse().unwrap(), 0))
                .await
                .unwrap(),
            "lo"
        );
    }
}
