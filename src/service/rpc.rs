// SPDX-License-Identifier: GPL-2.0-or-later
//! RPC dispatch and input conversion for an active kernel session.
use super::Service;
use crate::{
    backend::{self, Backend},
    error::{invalid, unsupported},
    rpc_api::*,
};

impl Kernel for Service {
    async fn open_session(
        self,
        _: tarpc::context::Context,
        config: SessionConfig,
    ) -> Result<SessionInfo> {
        self.open(config).await
    }
    async fn close_session(self, _: tarpc::context::Context) -> Result<()> {
        self.close()
    }
    async fn next_events(self, _: tarpc::context::Context) -> Result<Vec<Event>> {
        self.fetch_events().await
    }
    async fn allocate_spi(
        self,
        _: tarpc::context::Context,
        src: Endpoint,
        dst: Endpoint,
        protocol: u8,
        minimum: u32,
        maximum: u32,
    ) -> Result<u32> {
        self.request(|backend| {
            if protocol != 50 {
                return Err(unsupported());
            }
            let (src, dst) = (
                backend::validate_endpoint(src)?,
                backend::validate_endpoint(dst)?,
            );
            if src.family() != dst.family() || minimum < 256 || minimum > maximum {
                return Err(invalid());
            }
            backend.sas.allocate(src, dst, protocol, minimum, maximum)
        })
    }
    async fn allocate_cpi(
        self,
        _: tarpc::context::Context,
        _src: Endpoint,
        _dst: Endpoint,
    ) -> Result<u16> {
        self.request(|_| Err(unsupported()))
    }
    async fn install_sa(
        self,
        _: tarpc::context::Context,
        id: SaId,
        config: SaConfig,
    ) -> Result<()> {
        self.request(|backend| backend.install_sa(id, config))
    }
    async fn update_sa(
        self,
        _: tarpc::context::Context,
        _id: SaId,
        _config: SaUpdate,
    ) -> Result<()> {
        self.request(|_| Err(unsupported()))
    }
    async fn query_sa(self, _: tarpc::context::Context, id: SaId, cpi: u16) -> Result<SaUsage> {
        self.request(|backend| {
            if cpi != 0 {
                return Err(unsupported());
            }
            backend.sas.query(&backend::sa_id(id)?)
        })
    }
    async fn remove_sa(self, _: tarpc::context::Context, id: SaId, cpi: u16) -> Result<()> {
        self.request(|backend| {
            if cpi != 0 {
                return Err(unsupported());
            }
            backend.remove_sa(id)
        })
    }
    async fn flush_sas(self, _: tarpc::context::Context) -> Result<()> {
        self.request(Backend::flush_sas)
    }
    async fn install_policy(
        self,
        _: tarpc::context::Context,
        id: PolicyId,
        config: PolicyConfig,
    ) -> Result<()> {
        self.request(|backend| {
            backend
                .policies
                .add_policy(backend::policy_id(id)?, backend::policy_config(config)?)
        })
    }
    async fn remove_policy(
        self,
        _: tarpc::context::Context,
        id: PolicyId,
        config: PolicyConfig,
    ) -> Result<()> {
        self.request(|backend| {
            backend
                .policies
                .delete_policy(&backend::policy_id(id)?, &backend::policy_config(config)?)
        })
    }
    async fn query_policy(self, _: tarpc::context::Context, id: PolicyId) -> Result<u64> {
        self.request(|backend| backend.policies.query_policy(&backend::policy_id(id)?))
    }
    async fn flush_policies(self, _: tarpc::context::Context) -> Result<()> {
        self.request(|backend| backend.policies.flush_policies())
    }
    async fn bypass_port(self, _: tarpc::context::Context, family: u16, port: u16) -> Result<()> {
        self.request(|backend| {
            if ![libc::AF_INET as u16, libc::AF_INET6 as u16].contains(&family) || port < 1024 {
                return Err(invalid());
            }
            backend.policies.port_bypass(family, port)
        })
    }
    async fn get_source_address(
        self,
        _: tarpc::context::Context,
        destination: Endpoint,
        source: Option<Endpoint>,
    ) -> Result<Endpoint> {
        self.request(|backend| {
            let src = source.map(backend::validate_endpoint).transpose()?;
            let (host, _, _) =
                backend
                    .net
                    .lookup(&backend::validate_endpoint(destination)?, src.as_ref(), -1)?;
            Ok(host)
        })
    }
    async fn get_next_hop(
        self,
        _: tarpc::context::Context,
        destination: Endpoint,
        source: Option<Endpoint>,
        prefix: Option<i32>,
    ) -> Result<NextHop> {
        self.request(|backend| {
            let dst = backend::validate_endpoint(destination)?;
            let src = source.map(backend::validate_endpoint).transpose()?;
            let prefix = prefix.unwrap_or(-1);
            if prefix < -1 || prefix > dst.bits().into() {
                return Err(invalid());
            }
            let (_, gateway, interface) = backend.net.lookup(&dst, src.as_ref(), prefix)?;
            Ok(NextHop { gateway, interface })
        })
    }
    async fn get_interface(self, _: tarpc::context::Context, address: Endpoint) -> Result<String> {
        self.request(|backend| backend.net.interface(&backend::validate_endpoint(address)?))
    }
    async fn list_addresses(
        self,
        _: tarpc::context::Context,
        which: AddressTypes,
    ) -> Result<Vec<Endpoint>> {
        self.request(|backend| backend.net.enumerate(which))
    }
    async fn list_subnets(self, _: tarpc::context::Context) -> Result<Vec<Subnet>> {
        self.request(|backend| {
            backend.net.subnets().map(|subnets| {
                subnets
                    .into_iter()
                    .map(|(address, prefix, interface)| Subnet {
                        address,
                        prefix,
                        interface,
                    })
                    .collect()
            })
        })
    }
}
