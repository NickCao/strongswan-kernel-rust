// SPDX-License-Identifier: GPL-2.0-or-later
use crate::Endpoint;
use std::{
    io,
    net::{IpAddr, SocketAddr, SocketAddrV6},
};

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
