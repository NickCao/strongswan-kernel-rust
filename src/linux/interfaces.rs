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
use std::io;

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
}
impl InterfaceHandle {
    fn from_link(link: &Link, id: Option<InterfaceId>) -> Self {
        Self {
            index: link.index,
            id,
        }
    }
}
impl crate::interfaces::InterfaceHandle for InterfaceHandle {
    fn id(&self) -> Option<InterfaceId> {
        self.id
    }
}

pub struct LinuxInterfaces {
    net: Network,
    prefix: String,
    group: u32,
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
        })
    }

    fn name(&self, id: InterfaceId) -> String {
        format!("{}{id}", self.prefix)
    }

    fn id(&self, link: &Link) -> Option<InterfaceId> {
        link.name.strip_prefix(&self.prefix)?.parse().ok()
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
        links
            .iter()
            .filter(|link| link.group == self.group)
            .map(|link| {
                let id = self.id(link);
                let handle = InterfaceHandle::from_link(link, id);
                let config = if let Some(if_id) = link.xfrm_if_id {
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
            .collect()
    }

    fn create(&mut self, spec: &InterfaceSpec) -> io::Result<InterfaceHandle> {
        let mut message = self.settings(spec, 0)?;
        message.attributes.push(LinkAttribute::Group(self.group));
        self.net.request(
            RouteNetlinkMessage::NewLink(message),
            NlmF::ACK | NlmF::CREATE | NlmF::EXCL,
        )?;
        Ok(InterfaceHandle {
            index: network::index(&self.name(spec.id))?,
            id: Some(spec.id),
        })
    }

    fn update(&mut self, handle: &InterfaceHandle, spec: &InterfaceSpec) -> io::Result<()> {
        let current = self
            .net
            .link(handle.index)?
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENODEV))?;
        let message = self.settings(spec, handle.index)?;
        if current.xfrm_if_id.is_none() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interfaces::InterfaceHandle as _;
    use std::process::Command;

    fn ip(args: &[&str]) {
        let output = Command::new("ip").args(args).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "requires root and iproute2; creates a network namespace"]
    fn mutations_target_the_current_interface_at_the_handle_index() {
        let _namespace = crate::test_netns::Netns::new();
        let mut kernel = LinuxInterfaces::new("idx".into(), DEFAULT_INTERFACE_GROUP).unwrap();
        let mut net = Network::new().unwrap();
        let mut spec = InterfaceSpec {
            id: "00000007".parse().unwrap(),
            config: InterfaceConfig {
                if_id: 41,
                mtu: 1400,
                master: None,
                up: true,
                multicast: true,
            },
        };
        let original = kernel.create(&spec).unwrap();
        // The index remains the key after group, name and native settings change.
        ip(&[
            "link",
            "set",
            "idx00000007",
            "group",
            "0",
            "name",
            "changed",
        ]);
        ip(&["link", "set", "changed", "type", "xfrm", "if_id", "66"]);
        assert!(kernel.list().unwrap().is_empty());
        spec.id = "00000008".parse().unwrap();
        spec.config.if_id = 42;
        spec.config.mtu = 1300;
        kernel.update(&original, &spec).unwrap();
        let current = net.link(original.index).unwrap().unwrap();
        assert_eq!(current.name, "idx00000008");
        assert_eq!(current.group, 0);
        assert_eq!(current.xfrm_if_id, Some(42));
        assert_eq!(current.mtu, 1300);

        // A wrong-type replacement at the same key is repaired by update().
        ip(&["link", "del", "idx00000008"]);
        ip(&[
            "link",
            "add",
            "replacement",
            "index",
            &original.index.to_string(),
            "type",
            "dummy",
        ]);
        kernel.update(&original, &spec).unwrap();
        let recreated = kernel.list().unwrap().pop().unwrap();
        assert_eq!(recreated.handle.id(), Some(spec.id));
        assert_eq!(recreated.config, Some(spec.config));
        ip(&[
            "link",
            "set",
            "idx00000008",
            "group",
            "0",
            "name",
            "released",
        ]);
        kernel.delete(&recreated.handle).unwrap();
        assert!(net.link(recreated.handle.index).unwrap().is_none());
        kernel.delete(&recreated.handle).unwrap();

        // Deletion also uses the index directly when the kernel reuses it.
        ip(&[
            "link",
            "add",
            "reused",
            "index",
            &recreated.handle.index.to_string(),
            "type",
            "dummy",
        ]);
        kernel.delete(&recreated.handle).unwrap();
        assert!(net.link(recreated.handle.index).unwrap().is_none());
    }
}
