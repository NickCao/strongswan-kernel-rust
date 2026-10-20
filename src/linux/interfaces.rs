// SPDX-License-Identifier: GPL-2.0-or-later
//! Linux interface CRUD, ownership groups and naming. Lifecycle and repair
//! decisions live in the shared interface controller.
use super::{
    netlink::NlmF,
    network::{self, Link, Network},
};
use crate::{
    error::invalid,
    interfaces::{InterfaceConfig, InterfaceId, InterfaceKernel, InterfaceSpec, ObservedInterface},
};
use netlink_packet_route::{
    link::{InfoData, InfoKind, InfoXfrm, LinkAttribute, LinkFlags, LinkInfo, LinkMessage},
    RouteNetlinkMessage,
};
use std::{collections::HashMap, io};

pub const DEFAULT_INTERFACE_GROUP: u32 = 17227;

pub fn name_prefix(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() + 8 >= libc::IFNAMSIZ
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err("expected 1–7 ASCII letters, digits, underscores, or hyphens".into());
    }
    Ok(value.to_owned())
}

#[derive(Clone, Debug)]
pub struct InterfaceHandle {
    index: u32,
    id: Option<InterfaceId>,
    xfrm: Option<(u32, u32)>,
    name: String,
    expected_name: Option<String>,
}
impl InterfaceHandle {
    fn from_link(link: &Link, id: Option<InterfaceId>, expected_name: Option<String>) -> Self {
        Self {
            index: link.index,
            id,
            xfrm: link.xfrm,
            name: link.name.clone(),
            expected_name,
        }
    }
}
impl crate::interfaces::InterfaceHandle for InterfaceHandle {
    fn id(&self) -> Option<InterfaceId> {
        self.id
    }
    fn needs_reconcile(&self) -> bool {
        self.expected_name
            .as_ref()
            .is_some_and(|name| name != &self.name)
    }
}

pub struct LinuxInterfaces {
    net: Network,
    prefix: String,
    group: u32,
    // Preserve opaque identities through external renames. This is only an
    // association cache: group membership alone determines ownership.
    identities: HashMap<u32, InterfaceHandle>,
}
impl LinuxInterfaces {
    pub fn new(prefix: String, group: u32) -> io::Result<Self> {
        name_prefix(&prefix).map_err(io::Error::other)?;
        if group == 0 {
            return Err(invalid());
        }
        Ok(Self {
            net: Network::new()?,
            prefix,
            group,
            identities: HashMap::new(),
        })
    }

    fn current(&mut self, handle: &InterfaceHandle) -> io::Result<Option<Link>> {
        Ok(self
            .net
            .link(handle.index)?
            .filter(|link| link.group == self.group && link.xfrm == handle.xfrm))
    }

    fn name(&self, id: InterfaceId) -> String {
        format!("{}{id}", self.prefix)
    }

    fn id(&self, link: &Link) -> Option<InterfaceId> {
        self.identities
            .get(&link.index)
            .filter(|handle| {
                handle.xfrm.map(|(_, physical)| physical) == link.xfrm.map(|(_, physical)| physical)
            })
            .and_then(|handle| handle.id)
            .or_else(|| link.name.strip_prefix(&self.prefix)?.parse().ok())
    }

    fn settings(&self, spec: &InterfaceSpec, index: u32) -> io::Result<LinkMessage> {
        if spec.config.if_id == 0 {
            return Err(invalid());
        }
        let mut message = LinkMessage::default();
        message.header.index = index;
        message.header.change_mask = LinkFlags::Up | LinkFlags::Multicast;
        if spec.config.up {
            message.header.flags |= LinkFlags::Up;
        }
        if spec.config.multicast {
            message.header.flags |= LinkFlags::Multicast;
        }
        message.attributes = vec![
            LinkAttribute::IfName(self.name(spec.id)),
            LinkAttribute::Mtu(spec.config.mtu),
            LinkAttribute::Controller(match &spec.config.master {
                Some(name) => network::index(name)?,
                None => 0,
            }),
            LinkAttribute::LinkInfo(vec![
                LinkInfo::Kind(InfoKind::Xfrm),
                LinkInfo::Data(InfoData::Xfrm(vec![InfoXfrm::IfId(spec.config.if_id)])),
            ]),
        ];
        Ok(message)
    }
}

impl InterfaceKernel for LinuxInterfaces {
    type Handle = InterfaceHandle;

    fn list(&mut self) -> io::Result<Vec<ObservedInterface<InterfaceHandle>>> {
        let links = self.net.links()?;
        let observed: Vec<_> = links
            .iter()
            .filter(|link| link.group == self.group)
            .map(|link| {
                let id = self.id(link);
                let handle = InterfaceHandle::from_link(link, id, id.map(|id| self.name(id)));
                let config = if let Some((if_id, _)) = link.xfrm {
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
                    Some(InterfaceConfig {
                        if_id,
                        mtu: link.mtu,
                        master,
                        up: link.flags.contains(LinkFlags::Up),
                        multicast: link.flags.contains(LinkFlags::Multicast),
                    })
                } else {
                    None
                };
                Ok(ObservedInterface { handle, config })
            })
            .collect::<io::Result<_>>()?;
        self.identities = observed
            .iter()
            .filter(|entry| entry.handle.id.is_some())
            .map(|entry| (entry.handle.index, entry.handle.clone()))
            .collect();
        Ok(observed)
    }

    fn create(&mut self, spec: &InterfaceSpec) -> io::Result<InterfaceHandle> {
        let mut message = self.settings(spec, 0)?;
        message.attributes.push(LinkAttribute::Group(self.group));
        self.net.request(
            RouteNetlinkMessage::NewLink(message),
            NlmF::ACK | NlmF::CREATE | NlmF::EXCL,
        )?;
        let handle = InterfaceHandle {
            index: network::index(&self.name(spec.id))?,
            id: Some(spec.id),
            xfrm: Some((spec.config.if_id, 0)),
            name: self.name(spec.id),
            expected_name: Some(self.name(spec.id)),
        };
        self.identities.insert(handle.index, handle.clone());
        Ok(handle)
    }

    fn update(&mut self, handle: &InterfaceHandle, spec: &InterfaceSpec) -> io::Result<()> {
        if handle.id != Some(spec.id) {
            return Err(invalid());
        }
        let current = self
            .current(handle)?
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ESTALE))?;
        let message = self.settings(spec, handle.index)?;
        if current.xfrm.is_none() {
            // Linux cannot change an interface's kind. Replacement is a
            // backend implementation detail of updating this logical object.
            self.delete(handle)?;
            self.create(spec)?;
            return Ok(());
        }
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
            Ok(_) => {
                self.identities.remove(&handle.index);
                Ok(())
            }
            Err(error) if error.raw_os_error() == Some(libc::ENODEV) => {
                self.identities.remove(&handle.index);
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}
