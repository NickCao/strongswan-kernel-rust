// SPDX-License-Identifier: GPL-2.0-or-later
//! Desired policy ownership and reconciliation, independent of the device API.
use crate::{error::invalid, model::*};
use ipnet::IpNet;
use std::{collections::HashMap, io, net::IpAddr};

fn missing() -> io::Error {
    io::Error::from_raw_os_error(libc::ENOENT)
}

/// Canonical policy identity, independent of priority, templates and
/// device-assigned policy indices.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PolicyKey {
    pub src: IpNet,
    pub dst: IpNet,
    pub src_port: u16,
    pub src_port_mask: u16,
    pub dst_port: u16,
    pub dst_port_mask: u16,
    pub protocol: u8,
    pub dir: u8,
    pub mark: Mark,
    pub if_id: u32,
}
impl PolicyKey {
    pub fn new(id: &PolicyId) -> io::Result<Self> {
        if id.src.from.family() != id.dst.from.family() {
            return Err(invalid());
        }
        let (src, src_prefix) = id.src.subnet();
        let (dst, dst_prefix) = id.dst.subnet();
        let protocol = id.src.proto.max(id.dst.proto);
        let (mut src_port, mut src_port_mask) = id.src.ports();
        let (mut dst_port, mut dst_port_mask) = id.dst.ports();
        if [1, 58].contains(&protocol) && (src_port != 0 || dst_port != 0) {
            let port = src_port.max(dst_port);
            src_port = port >> 8;
            dst_port = port & 0xff;
            src_port_mask = if src_port == 0 { 0 } else { u16::MAX };
            dst_port_mask = if dst_port == 0 { 0 } else { u16::MAX };
        }
        Ok(Self {
            src: IpNet::new(src.ip, src_prefix).map_err(|_| invalid())?,
            dst: IpNet::new(dst.ip, dst_prefix).map_err(|_| invalid())?,
            src_port,
            src_port_mask,
            dst_port,
            dst_port_mask,
            protocol,
            dir: id.dir,
            mark: Mark {
                value: id.mark.value & id.mark.mask,
                mask: id.mark.mask,
            },
            if_id: id.if_id,
        })
    }

    fn priority(&self, data: &PolicyData) -> (u32, u32) {
        let base = match data.prio {
            0 => 200000,
            3 => 600000,
            _ => 400000,
        };
        let auto = base
            - (self.src.prefix_len() as u32 + self.dst.prefix_len() as u32) * 512
            - if self.protocol != 0 { 256 } else { 0 }
            - (self.src_port_mask.count_ones() + self.dst_port_mask.count_ones()) * 4
            - u32::from(data.prio != 2);
        (
            if data.manual_prio == 0 {
                auto
            } else {
                data.manual_prio
            },
            auto,
        )
    }

    fn spec(&self, data: &PolicyData) -> PolicySpec {
        PolicySpec {
            id: self.clone(),
            config: PolicyConfig {
                priority: self.priority(data).0,
                block: data.kind == 3,
                template: (data.kind == 1 && data.reqid != 0).then(|| PolicyTemplate {
                    src: data.src.ip,
                    dst: data.dst.ip,
                    reqid: data.reqid,
                    spi: if self.dir == 1 {
                        data.esp.unwrap_or(0)
                    } else {
                        0
                    },
                }),
            },
        }
    }
}

/// The supported protection template: tunnel-mode ESP, with SPI zero accepting
/// any matching SA (including overlapping inbound SAs during rekey).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyTemplate {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub reqid: u32,
    pub spi: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyConfig {
    pub priority: u32,
    pub block: bool,
    pub template: Option<PolicyTemplate>,
}
/// Resolved configuration passed to the device backend after selecting the
/// winning strongSwan reference and calculating its effective priority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicySpec {
    pub id: PolicyKey,
    pub config: PolicyConfig,
}
impl PolicySpec {
    pub fn new(id: &PolicyId, data: &PolicyData) -> io::Result<Self> {
        Ok(PolicyKey::new(id)?.spec(data))
    }
}
#[derive(Clone, Debug)]
pub struct ObservedPolicy<H> {
    pub handle: H,
    pub id: PolicyKey,
    /// None if native configuration cannot be represented by our supported
    /// model. The controller repairs such entries only if it owns the handle.
    pub config: Option<PolicyConfig>,
    /// Last use in CLOCK_MONOTONIC seconds, or zero if unused/unavailable.
    pub last_use: u64,
}

/// Policy CRUD with normalized observations and opaque device handles. Policy
/// identity, priority selection and reconciliation belong to the controller.
pub trait PolicyKernel: Send {
    type Handle: Clone + Eq;
    fn list(&mut self) -> io::Result<Vec<ObservedPolicy<Self::Handle>>>;
    fn get(&mut self, handle: &Self::Handle) -> io::Result<ObservedPolicy<Self::Handle>>;
    /// Create only: an existing policy must not be adopted or replaced.
    fn create(&mut self, spec: &PolicySpec) -> io::Result<Self::Handle>;
    /// Update the object identified by this handle without changing its
    /// identity. A backend may upsert when its native API preserves the handle;
    /// otherwise a missing object returns NotFound.
    fn update(&mut self, handle: &Self::Handle, spec: &PolicySpec) -> io::Result<()>;
    /// An already absent object counts as successfully deleted. A replacement
    /// object that does not match the handle must be left untouched.
    fn delete(&mut self, handle: &Self::Handle) -> io::Result<()>;
}

struct PolicyState<H> {
    handle: H,
    used_by: Vec<PolicyData>,
}

pub struct Policies<K: PolicyKernel> {
    kernel: K,
    policies: HashMap<PolicyKey, PolicyState<K::Handle>>,
    bypasses: Vec<(PolicyId, PolicyData)>,
}
impl<K: PolicyKernel> Policies<K> {
    pub fn new(kernel: K) -> Self {
        Self {
            kernel,
            policies: HashMap::new(),
            bypasses: Vec::new(),
        }
    }
    fn update(kernel: &mut K, handle: &K::Handle, spec: &PolicySpec) -> io::Result<K::Handle> {
        match kernel.update(handle, spec) {
            Ok(()) => Ok(handle.clone()),
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::ESRCH) =>
            {
                kernel.create(spec)
            }
            Err(error) => Err(error),
        }
    }
    pub fn add_policy(&mut self, id: PolicyId, data: PolicyData) -> io::Result<()> {
        let key = PolicyKey::new(&id)?;
        let current = self.policies.get(&key);
        let mut uses = current.map(|p| p.used_by.clone()).unwrap_or_default();
        let mut handle = current.map(|p| p.handle.clone());
        let priority = key.priority(&data);
        let mut pos = uses.len();
        for (index, existing_data) in uses.iter().enumerate() {
            let existing = key.priority(existing_data);
            if existing > priority
                || (existing == priority && (existing_data.reqid == 0 || data.reqid != 0))
            {
                pos = index;
                break;
            }
        }
        if pos == 0 {
            let spec = key.spec(&data);
            handle = Some(match handle {
                Some(handle) => Self::update(&mut self.kernel, &handle, &spec)?,
                None => self.kernel.create(&spec)?,
            });
        }
        uses.insert(pos, data);
        self.policies.insert(
            key,
            PolicyState {
                handle: handle.unwrap(),
                used_by: uses,
            },
        );
        Ok(())
    }
    pub fn delete_policy(&mut self, id: &PolicyId, data: &PolicyData) -> io::Result<()> {
        let key = PolicyKey::new(id)?;
        let state = self.policies.get(&key).ok_or_else(missing)?;
        let mut handle = state.handle.clone();
        let mut uses = state.used_by.clone();
        let pos = uses.iter().position(|p| p == data).ok_or_else(missing)?;
        uses.remove(pos);
        if uses.is_empty() {
            self.kernel.delete(&handle)?;
            self.policies.remove(&key);
        } else {
            if pos == 0 {
                handle = Self::update(&mut self.kernel, &handle, &key.spec(&uses[0]))?;
            }
            let state = self.policies.get_mut(&key).unwrap();
            state.handle = handle;
            state.used_by = uses;
        }
        Ok(())
    }
    pub fn query_policy(&mut self, id: &PolicyId) -> io::Result<u64> {
        let state = self
            .policies
            .get(&PolicyKey::new(id)?)
            .ok_or_else(missing)?;
        Ok(self.kernel.get(&state.handle)?.last_use)
    }
    pub fn contains_reqid(&self, if_id: u32, reqid: u32) -> bool {
        self.policies.iter().any(|(key, policy)| {
            key.if_id == if_id && policy.used_by.iter().any(|data| data.reqid == reqid)
        })
    }
    /// The caller holds the same lock as add/delete throughout observation and
    /// repair, so no stale desired snapshot can outlive a deletion.
    pub fn reconcile(&mut self) -> io::Result<()> {
        if self.policies.is_empty() {
            return Ok(());
        }
        let observed: HashMap<_, _> = self
            .kernel
            .list()?
            .into_iter()
            .map(|entry| (entry.id.clone(), entry))
            .collect();
        let mut first_error = None;
        for (id, state) in &mut self.policies {
            let spec = id.spec(&state.used_by[0]);
            let result = match observed.get(id) {
                Some(entry) if entry.handle != state.handle => {
                    Err(io::Error::from_raw_os_error(libc::EEXIST))
                }
                Some(entry) if entry.config.as_ref() == Some(&spec.config) => Ok(()),
                Some(_) => Self::update(&mut self.kernel, &state.handle, &spec)
                    .map(|handle| state.handle = handle),
                None => self
                    .kernel
                    .create(&spec)
                    .map(|handle| state.handle = handle),
            };
            if let Err(error) = result {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
    pub fn flush_policies(&mut self) -> io::Result<()> {
        let keys: Vec<_> = self
            .policies
            .keys()
            .filter(|key| key.if_id != 0)
            .cloned()
            .collect();
        for key in keys {
            self.kernel.delete(&self.policies[&key].handle)?;
            self.policies.remove(&key);
        }
        Ok(())
    }
    pub fn port_bypass(&mut self, family: u16, port: u16) -> io::Result<()> {
        if port == 0 {
            return Err(invalid());
        }
        let any = Host::any(family)?;
        for dir in [1, 0] {
            let wildcard = Ts::from_subnet(any.clone(), 0, 17, 0, 65535)?;
            let specific = Ts::from_subnet(any.clone(), 0, 17, port, port)?;
            let (src, dst) = if dir == 1 {
                (specific, wildcard)
            } else {
                (wildcard, specific)
            };
            let id = PolicyId {
                dir,
                src,
                dst,
                mark: Mark::default(),
                if_id: 0,
            };
            if self.bypasses.iter().any(|(p, _)| p == &id) {
                continue;
            }
            let data = PolicyData {
                kind: 2,
                prio: 0,
                manual_prio: 32,
                src: any.clone(),
                dst: any.clone(),
                reqid: 0,
                policy_count: 1,
                esp: None,
            };
            self.add_policy(id.clone(), data.clone())?;
            self.bypasses.push((id, data));
        }
        Ok(())
    }
    pub fn remove_bypasses(&mut self) -> io::Result<()> {
        while let Some((id, data)) = self.bypasses.last().cloned() {
            self.delete_policy(&id, &data)?;
            self.bypasses.pop();
        }
        Ok(())
    }
    pub fn has_tunnel_policies(&self) -> bool {
        self.policies.keys().any(|key| key.if_id != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemoryKernel {
        installed: HashMap<PolicyKey, ObservedPolicy<u64>>,
        next: u64,
        writes: usize,
        lists: usize,
        reject_write: bool,
    }
    impl MemoryKernel {
        fn insert(&mut self, spec: PolicySpec) -> u64 {
            self.next += 1;
            self.installed.insert(
                spec.id.clone(),
                ObservedPolicy {
                    handle: self.next,
                    id: spec.id,
                    config: Some(spec.config),
                    last_use: 0,
                },
            );
            self.next
        }
    }
    impl PolicyKernel for MemoryKernel {
        type Handle = u64;
        fn list(&mut self) -> io::Result<Vec<ObservedPolicy<u64>>> {
            self.lists += 1;
            Ok(self.installed.values().cloned().collect())
        }
        fn get(&mut self, handle: &u64) -> io::Result<ObservedPolicy<u64>> {
            self.installed
                .values()
                .find(|entry| entry.handle == *handle)
                .cloned()
                .ok_or_else(missing)
        }
        fn create(&mut self, spec: &PolicySpec) -> io::Result<u64> {
            if self.reject_write {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            if self.installed.contains_key(&spec.id) {
                return Err(io::Error::from_raw_os_error(libc::EEXIST));
            }
            self.writes += 1;
            Ok(self.insert(spec.clone()))
        }
        fn update(&mut self, handle: &u64, spec: &PolicySpec) -> io::Result<()> {
            if self.reject_write {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            let entry = self
                .installed
                .values_mut()
                .find(|entry| entry.handle == *handle)
                .ok_or_else(missing)?;
            if entry.id != spec.id {
                return Err(invalid());
            }
            entry.config = Some(spec.config.clone());
            self.writes += 1;
            Ok(())
        }
        fn delete(&mut self, handle: &u64) -> io::Result<()> {
            self.installed.retain(|_, entry| entry.handle != *handle);
            Ok(())
        }
    }
    fn fixture() -> (PolicyId, PolicyData) {
        let src = Host {
            ip: "192.0.2.1".parse().unwrap(),
            port: 0,
        };
        let dst = Host {
            ip: "192.0.2.2".parse().unwrap(),
            port: 0,
        };
        (
            PolicyId {
                src: Ts::from_subnet(src.clone(), 0, 0, 0, u16::MAX).unwrap(),
                dst: Ts::from_subnet(dst.clone(), 0, 0, 0, u16::MAX).unwrap(),
                dir: 1,
                mark: Mark::default(),
                if_id: 41,
            },
            PolicyData {
                src,
                dst,
                kind: 1,
                prio: 1,
                manual_prio: 100,
                reqid: 42,
                policy_count: 2,
                esp: Some(0x10203),
            },
        )
    }

    #[test]
    fn repairs_follow_current_ownership_and_rekey_precedence() {
        let (id, old) = fixture();
        let key = PolicyKey::new(&id).unwrap();
        let old_spec = key.spec(&old);
        let mut new = old.clone();
        new.esp = Some(0x10204);
        let new_spec = key.spec(&new);
        let mut foreign = id.clone();
        foreign.if_id = 99;
        let foreign_spec = PolicySpec::new(&foreign, &old).unwrap();
        let mut kernel = MemoryKernel::default();
        kernel.insert(foreign_spec.clone());
        let mut policies = Policies::new(kernel);
        policies.add_policy(id.clone(), old.clone()).unwrap();
        policies.add_policy(id.clone(), new.clone()).unwrap();
        policies.kernel.installed.get_mut(&key).unwrap().config = Some(old_spec.config.clone());
        policies.reconcile().unwrap();
        assert_eq!(
            policies.kernel.installed[&key].config.as_ref(),
            Some(&new_spec.config)
        );
        let previous_handle = policies.kernel.installed.remove(&key).unwrap().handle;
        policies.reconcile().unwrap();
        assert_ne!(policies.kernel.installed[&key].handle, previous_handle);
        assert_eq!(
            policies.kernel.installed[&key].config.as_ref(),
            Some(&new_spec.config)
        );
        let writes = policies.kernel.writes;
        policies.reconcile().unwrap();
        assert_eq!(
            policies.kernel.writes, writes,
            "matching policies must not be rewritten"
        );
        // A strict CRUD backend may require create after update finds an
        // externally removed policy, without reviving the removed reference.
        policies.kernel.installed.remove(&key);
        policies.delete_policy(&id, &new).unwrap();
        assert_eq!(
            policies.kernel.installed[&key].config.as_ref(),
            Some(&old_spec.config)
        );
        policies.kernel.installed.remove(&key);
        policies.delete_policy(&id, &old).unwrap();
        policies.reconcile().unwrap();
        assert_eq!(policies.kernel.installed.len(), 1);
        assert_eq!(
            policies.kernel.installed[&foreign_spec.id].config.as_ref(),
            Some(&foreign_spec.config)
        );
    }

    #[test]
    fn rejected_writes_do_not_change_desired_policies() {
        let (id, data) = fixture();
        let key = PolicyKey::new(&id).unwrap();
        let mut policies = Policies::new(MemoryKernel {
            reject_write: true,
            ..Default::default()
        });
        assert!(policies.add_policy(id.clone(), data.clone()).is_err());
        policies.kernel.reject_write = false;
        policies.reconcile().unwrap();
        assert!(policies.kernel.installed.is_empty());
        policies.add_policy(id.clone(), data.clone()).unwrap();
        let mut replacement = data.clone();
        replacement.esp = Some(0x99999);
        policies.kernel.reject_write = true;
        assert!(policies.add_policy(id, replacement).is_err());
        policies.kernel.reject_write = false;
        policies.kernel.installed.get_mut(&key).unwrap().config = None;
        policies.reconcile().unwrap();
        assert_eq!(
            policies.kernel.installed[&key].config.as_ref(),
            Some(&key.spec(&data).config)
        );
    }

    #[test]
    fn foreign_policies_are_not_adopted_even_with_identical_configuration() {
        let (id, data) = fixture();
        let spec = PolicySpec::new(&id, &data).unwrap();
        let mut policies = Policies::new(MemoryKernel::default());
        let foreign = policies.kernel.insert(spec.clone());
        assert_eq!(
            policies
                .add_policy(id.clone(), data.clone())
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EEXIST)
        );
        policies.reconcile().unwrap();
        assert_eq!(policies.kernel.writes, 0);
        policies.kernel.installed.clear();
        policies.add_policy(id, data).unwrap();
        let replacement = policies.kernel.insert(spec.clone());
        assert_ne!(foreign, replacement);
        assert_eq!(
            policies.reconcile().unwrap_err().raw_os_error(),
            Some(libc::EEXIST)
        );
        policies.flush_policies().unwrap();
        assert_eq!(policies.kernel.installed[&spec.id].handle, replacement);
    }

    #[test]
    fn usage_reads_one_policy_and_unsupported_configuration_is_repaired() {
        let (id, data) = fixture();
        let key = PolicyKey::new(&id).unwrap();
        let mut policies = Policies::new(MemoryKernel::default());
        policies.add_policy(id.clone(), data.clone()).unwrap();
        policies.kernel.installed.get_mut(&key).unwrap().last_use = 123;
        assert_eq!(policies.query_policy(&id).unwrap(), 123);
        assert_eq!(
            policies.kernel.lists, 0,
            "usage queries must not dump the table"
        );
        policies.kernel.installed.get_mut(&key).unwrap().config = None;
        policies.reconcile().unwrap();
        assert_eq!(
            policies.kernel.installed[&key].config.as_ref(),
            Some(&key.spec(&data).config)
        );
    }
}
