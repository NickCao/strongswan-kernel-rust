// SPDX-License-Identifier: GPL-2.0-or-later
use crate::Endpoint;
use rustix::net::AddressFamily;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
};

impl Endpoint {
    pub fn new(address: IpAddr, port: u16) -> Self {
        Self {
            address,
            port,
            flow_info: 0,
            scope_id: 0,
        }
    }
    pub fn family(&self) -> u16 {
        if self.address.is_ipv4() {
            AddressFamily::INET.as_raw()
        } else {
            AddressFamily::INET6.as_raw()
        }
    }
    pub fn bits(&self) -> u8 {
        if self.address.is_ipv4() {
            32
        } else {
            128
        }
    }
    pub fn any(family: u16) -> io::Result<Self> {
        let address = match AddressFamily::from_raw(family) {
            AddressFamily::INET => Ipv4Addr::UNSPECIFIED.into(),
            AddressFamily::INET6 => Ipv6Addr::UNSPECIFIED.into(),
            _ => return Err(io::ErrorKind::InvalidInput.into()),
        };
        Ok(Self::new(address, 0))
    }
    pub fn is_link_local(&self) -> bool {
        match self.address {
            IpAddr::V4(address) => address.is_link_local(),
            IpAddr::V6(address) => address.is_unicast_link_local(),
        }
    }
}

impl TryFrom<&Endpoint> for SocketAddr {
    type Error = io::Error;

    fn try_from(endpoint: &Endpoint) -> io::Result<Self> {
        match endpoint.address {
            IpAddr::V4(ip) if endpoint.flow_info == 0 && endpoint.scope_id == 0 => {
                Ok(Self::from((ip, endpoint.port)))
            }
            IpAddr::V6(ip) => {
                Ok(
                    SocketAddrV6::new(ip, endpoint.port, endpoint.flow_info, endpoint.scope_id)
                        .into(),
                )
            }
            _ => Err(io::ErrorKind::InvalidInput.into()),
        }
    }
}
impl From<SocketAddr> for Endpoint {
    fn from(address: SocketAddr) -> Self {
        let (flow_info, scope_id) = match address {
            SocketAddr::V4(_) => (0, 0),
            SocketAddr::V6(address) => (address.flowinfo(), address.scope_id()),
        };
        Self {
            address: address.ip(),
            port: address.port(),
            flow_info,
            scope_id,
        }
    }
}
