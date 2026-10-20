// SPDX-License-Identifier: GPL-2.0-or-later
//! Linux interface CRUD; lifecycle, ownership and repair decisions live in the
//! shared interface controller.
use crate::{
    error::invalid,
    interfaces::{InterfaceKernel, InterfaceSpec, ObservedInterface},
    netlink::NlmF,
    network::{self, Link, Network},
};
use netlink_packet_route::{
    link::{InfoData, InfoKind, InfoXfrm, LinkAttribute, LinkFlags, LinkInfo, LinkMessage},
    RouteNetlinkMessage,
};
use std::io;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceHandle {
    index: u32,
    id: u32,
    physical: u32,
}
impl InterfaceHandle {
    fn from_link(link: &Link) -> Option<Self> {
        link.xfrm.map(|(id, physical)| Self {
            index: link.index,
            id,
            physical,
        })
    }
}

pub struct LinuxInterfaces {
    net: Network,
}
impl LinuxInterfaces {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            net: Network::new()?,
        })
    }

    fn current(&mut self, handle: &InterfaceHandle) -> io::Result<Option<Link>> {
        Ok(self
            .net
            .link(handle.index)?
            .filter(|link| InterfaceHandle::from_link(link).as_ref() == Some(handle)))
    }

    fn settings(spec: &InterfaceSpec, index: u32) -> io::Result<LinkMessage> {
        if spec.id == 0 || spec.name.is_empty() || spec.name.len() >= libc::IFNAMSIZ {
            return Err(invalid());
        }
        let mut message = LinkMessage::default();
        message.header.index = index;
        message.header.change_mask = LinkFlags::Up | LinkFlags::Multicast;
        if spec.up {
            message.header.flags |= LinkFlags::Up;
        }
        if spec.multicast {
            message.header.flags |= LinkFlags::Multicast;
        }
        message.attributes = vec![
            LinkAttribute::IfName(spec.name.clone()),
            LinkAttribute::Mtu(spec.mtu),
            LinkAttribute::Controller(match &spec.master {
                Some(name) => network::index(name)?,
                None => 0,
            }),
        ];
        Ok(message)
    }
}

impl InterfaceKernel for LinuxInterfaces {
    type Handle = InterfaceHandle;

    fn list(&mut self) -> io::Result<Vec<ObservedInterface<InterfaceHandle>>> {
        let links = self.net.links()?;
        links
            .iter()
            .filter_map(|link| {
                let handle = InterfaceHandle::from_link(link)?;
                Some((|| {
                    let master = if link.master == 0 {
                        None
                    } else {
                        Some(
                            links
                                .iter()
                                .find(|other| other.index == link.master)
                                .ok_or_else(|| io::Error::from_raw_os_error(libc::ENODEV))?
                                .name
                                .clone(),
                        )
                    };
                    Ok(ObservedInterface {
                        config: InterfaceSpec {
                            id: handle.id,
                            name: link.name.clone(),
                            mtu: link.mtu,
                            master,
                            up: link.flags.contains(LinkFlags::Up),
                            multicast: link.flags.contains(LinkFlags::Multicast),
                        },
                        handle,
                    })
                })())
            })
            .collect()
    }

    fn create(&mut self, spec: &InterfaceSpec) -> io::Result<InterfaceHandle> {
        let mut message = Self::settings(spec, 0)?;
        message.attributes.push(LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Xfrm),
            LinkInfo::Data(InfoData::Xfrm(vec![InfoXfrm::IfId(spec.id)])),
        ]));
        self.net.request(
            RouteNetlinkMessage::NewLink(message),
            NlmF::ACK | NlmF::CREATE | NlmF::EXCL,
        )?;
        Ok(InterfaceHandle {
            index: network::index(&spec.name)?,
            id: spec.id,
            physical: 0,
        })
    }

    fn update(&mut self, handle: &InterfaceHandle, spec: &InterfaceSpec) -> io::Result<()> {
        if spec.id != handle.id {
            return Err(invalid());
        }
        self.current(handle)?
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ESTALE))?;
        let message = Self::settings(spec, handle.index)?;
        self.net
            .request(RouteNetlinkMessage::NewLink(message), NlmF::ACK)?;
        Ok(())
    }

    fn delete(&mut self, handle: &InterfaceHandle) -> io::Result<()> {
        if self.current(handle)?.is_none() {
            return Ok(());
        }
        let mut message = LinkMessage::default();
        message.header.index = handle.index;
        match self
            .net
            .request(RouteNetlinkMessage::DelLink(message), NlmF::ACK)
        {
            Ok(_) => Ok(()),
            Err(error) if error.raw_os_error() == Some(libc::ENODEV) => Ok(()),
            Err(error) => Err(error),
        }
    }
}
