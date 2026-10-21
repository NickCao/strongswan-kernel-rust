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
            src: IpNet::new(src.address, src_prefix).map_err(|_| invalid())?,
            dst: IpNet::new(dst.address, dst_prefix).map_err(|_| invalid())?,
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
                    src: data.src.address,
                    dst: data.dst.address,
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
#[cfg(test)]
impl PolicySpec {
    pub fn new(id: &PolicyId, data: &PolicyData) -> io::Result<Self> {
        Ok(PolicyKey::new(id)?.spec(data))
    }
}
#[derive(Clone, Debug)]
pub struct ObservedPolicy<H> {
    pub handle: H,
    /// None if native configuration cannot be represented by our model.
    /// A known desired identity is still repaired through update().
    pub config: Option<PolicyConfig>,
    /// Last use in CLOCK_MONOTONIC seconds, or zero if unused/unavailable.
    pub last_use: u64,
}

/// Logical identity captured by inventory, without device I/O.
pub trait PolicyHandle {
    fn id(&self) -> Option<&PolicyKey>;
}

/// CRUD for backend-owned policies, including leftovers after restart. The
/// backend defines ownership and the native keys used to target mutations.
/// Reference selection, desired configuration and repair belong to the caller.
pub trait PolicyKernel: Send {
    type Handle: PolicyHandle;
    fn list(&mut self) -> io::Result<Vec<ObservedPolicy<Self::Handle>>>;
    /// Look up a logical identity directly, including its usage and native
    /// handle, without requiring a full inventory for every strongSwan query.
    fn get(&mut self, id: &PolicyKey) -> io::Result<ObservedPolicy<Self::Handle>>;
    /// Create only. Existing owned policies are discovered by get()/list().
    fn create(&mut self, spec: &PolicySpec) -> io::Result<Self::Handle>;
    /// Achieve this configuration for the object identified by the handle.
    /// The backend chooses in-place repair or replacement. Obtain a fresh
    /// handle before addressing the object again after an update.
    fn update(&mut self, handle: &Self::Handle, spec: &PolicySpec) -> io::Result<()>;
    /// An already absent object counts as successfully deleted. The native
    /// key determines which object is targeted, including after key reuse.
    fn delete(&mut self, handle: &Self::Handle) -> io::Result<()>;
}

pub struct Policies<K: PolicyKernel> {
    kernel: K,
    policies: HashMap<PolicyKey, Vec<PolicyData>>,
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
    fn repair(
        kernel: &mut K,
        current: &ObservedPolicy<K::Handle>,
        spec: &PolicySpec,
    ) -> io::Result<()> {
        if current.config.as_ref() == Some(&spec.config) {
            return Ok(());
        }
        match kernel.update(&current.handle, spec) {
            Err(error) if is_missing(&error) => kernel.create(spec).map(|_| ()),
            result => result,
        }
    }
    fn ensure(&mut self, spec: &PolicySpec) -> io::Result<()> {
        match self.kernel.get(&spec.id) {
            Ok(current) => Self::repair(&mut self.kernel, &current, spec),
            Err(error) if is_missing(&error) => self.kernel.create(spec).map(|_| ()),
            Err(error) => Err(error),
        }
    }
    pub fn add_policy(&mut self, id: PolicyId, data: PolicyData) -> io::Result<()> {
        let key = PolicyKey::new(&id)?;
        let mut uses = self.policies.get(&key).cloned().unwrap_or_default();
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
            self.ensure(&key.spec(&data))?;
        }
        uses.insert(pos, data);
        self.policies.insert(key, uses);
        Ok(())
    }
    pub fn delete_policy(&mut self, id: &PolicyId, data: &PolicyData) -> io::Result<()> {
        let key = PolicyKey::new(id)?;
        let mut uses = self.policies.get(&key).ok_or_else(missing)?.clone();
        let pos = uses.iter().position(|p| p == data).ok_or_else(missing)?;
        uses.remove(pos);
        if uses.is_empty() {
            match self.kernel.get(&key) {
                Ok(current) => self.kernel.delete(&current.handle)?,
                Err(error) if is_missing(&error) => (),
                Err(error) => return Err(error),
            }
            self.policies.remove(&key);
        } else {
            if pos == 0 {
                self.ensure(&key.spec(&uses[0]))?;
            }
            self.policies.insert(key, uses);
        }
        Ok(())
    }
    pub fn query_policy(&mut self, id: &PolicyId) -> io::Result<u64> {
        let key = PolicyKey::new(id)?;
        if !self.policies.contains_key(&key) {
            return Err(missing());
        }
        Ok(self.kernel.get(&key)?.last_use)
    }
    pub fn contains_reqid(&self, if_id: u32, reqid: u32) -> bool {
        self.policies
            .iter()
            .any(|(key, uses)| key.if_id == if_id && uses.iter().any(|data| data.reqid == reqid))
    }
    /// Clear desired state. Backend inventory retains unwanted objects for
    /// deletion retries, including after a controller restart.
    pub fn clear(&mut self) {
        self.policies.clear();
        self.bypasses.clear();
    }
    /// The caller holds the same lock as add/delete throughout observation and
    /// repair, so no stale desired snapshot can outlive a deletion.
    pub fn reconcile(&mut self) -> io::Result<()> {
        let mut inventory = self.kernel.list()?;
        // Prefer a representable entry when several native objects claim the
        // same logical identity, as with interface inventory.
        inventory.sort_by_key(|entry| entry.config.is_none());
        let mut observed = HashMap::new();
        let mut first_error = None;
        for entry in inventory {
            if let Some(id) = entry
                .handle
                .id()
                .filter(|id| self.policies.contains_key(*id))
            {
                if let std::collections::hash_map::Entry::Vacant(slot) = observed.entry(id.clone())
                {
                    slot.insert(entry);
                    continue;
                }
            }
            if let Err(error) = self.kernel.delete(&entry.handle) {
                first_error.get_or_insert(error);
            }
        }
        for (id, uses) in &self.policies {
            let spec = id.spec(&uses[0]);
            let result = match observed.get(&spec.id) {
                Some(entry) => Self::repair(&mut self.kernel, entry, &spec),
                None => self.kernel.create(&spec).map(|_| ()),
            };
            if let Err(error) = result {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
    pub fn flush_policies(&mut self) -> io::Result<()> {
        self.policies.retain(|key, _| key.if_id == 0);
        self.reconcile()
    }
    pub fn port_bypass(&mut self, family: u16, port: u16) -> io::Result<()> {
        if port == 0 {
            return Err(invalid());
        }
        let any = Endpoint::any(family)?;
        for dir in [1, 0] {
            let wildcard = Ts::from_subnet(any, 0, 17, 0, 65535)?;
            let specific = Ts::from_subnet(any, 0, 17, port, port)?;
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
                src: any,
                dst: any,
                reqid: 0,
                policy_count: 1,
                esp: None,
            };
            self.add_policy(id.clone(), data.clone())?;
            self.bypasses.push((id, data));
        }
        Ok(())
    }
    pub fn has_tunnel_policies(&self) -> bool {
        self.policies.keys().any(|key| key.if_id != 0)
    }
}

fn is_missing(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct MemoryHandle {
        index: u64,
        id: Option<PolicyKey>,
    }
    impl PolicyHandle for MemoryHandle {
        fn id(&self) -> Option<&PolicyKey> {
            self.id.as_ref()
        }
    }
    #[derive(Default)]
    struct MemoryKernel {
        installed: HashMap<PolicyKey, ObservedPolicy<MemoryHandle>>,
        next: u64,
        writes: usize,
        lists: usize,
        reject_write: bool,
        reject_delete: std::collections::HashSet<u64>,
    }
    impl MemoryKernel {
        fn insert(&mut self, spec: PolicySpec) -> u64 {
            self.next += 1;
            self.installed.insert(
                spec.id.clone(),
                ObservedPolicy {
                    handle: MemoryHandle {
                        index: self.next,
                        id: Some(spec.id),
                    },
                    config: Some(spec.config),
                    last_use: 0,
                },
            );
            self.next
        }
    }
    impl PolicyKernel for MemoryKernel {
        type Handle = MemoryHandle;
        fn list(&mut self) -> io::Result<Vec<ObservedPolicy<MemoryHandle>>> {
            self.lists += 1;
            Ok(self.installed.values().cloned().collect())
        }
        fn get(&mut self, id: &PolicyKey) -> io::Result<ObservedPolicy<MemoryHandle>> {
            self.installed
                .values()
                .find(|entry| entry.handle.id() == Some(id))
                .cloned()
                .ok_or_else(missing)
        }
        fn create(&mut self, spec: &PolicySpec) -> io::Result<MemoryHandle> {
            if self.reject_write {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            if self.installed.contains_key(&spec.id) {
                return Err(io::Error::from_raw_os_error(libc::EEXIST));
            }
            self.writes += 1;
            let index = self.insert(spec.clone());
            Ok(MemoryHandle {
                index,
                id: Some(spec.id.clone()),
            })
        }
        fn update(&mut self, handle: &MemoryHandle, spec: &PolicySpec) -> io::Result<()> {
            if self.reject_write {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            let entry = self
                .installed
                .values_mut()
                .find(|entry| entry.handle.index == handle.index)
                .ok_or_else(missing)?;
            assert_eq!(entry.handle.id(), Some(&spec.id));
            entry.config = Some(spec.config.clone());
            self.writes += 1;
            Ok(())
        }
        fn delete(&mut self, handle: &MemoryHandle) -> io::Result<()> {
            if self.reject_delete.contains(&handle.index) {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            self.installed
                .retain(|_, entry| entry.handle.index != handle.index);
            Ok(())
        }
    }
    fn fixture() -> (PolicyId, PolicyData) {
        let src = Endpoint::new("192.0.2.1".parse().unwrap(), 0);
        let dst = Endpoint::new("192.0.2.2".parse().unwrap(), 0);
        (
            PolicyId {
                src: Ts::from_subnet(src, 0, 0, 0, u16::MAX).unwrap(),
                dst: Ts::from_subnet(dst, 0, 0, 0, u16::MAX).unwrap(),
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
    fn repairs_follow_current_desires_and_rekey_precedence() {
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
        let previous_handle = policies.kernel.installed.remove(&key).unwrap().handle.index;
        policies.reconcile().unwrap();
        assert_ne!(
            policies.kernel.installed[&key].handle.index,
            previous_handle
        );
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
        assert!(policies.kernel.installed.is_empty());
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
    fn existing_policies_and_replacements_are_discovered_without_cached_handles() {
        let (id, data) = fixture();
        let spec = PolicySpec::new(&id, &data).unwrap();
        let mut policies = Policies::new(MemoryKernel::default());
        let previous = policies.kernel.insert(spec.clone());
        policies.add_policy(id.clone(), data.clone()).unwrap();
        policies.reconcile().unwrap();
        assert_eq!(policies.kernel.writes, 0);
        let replacement = policies.kernel.insert(spec.clone());
        assert_ne!(previous, replacement);
        policies.reconcile().unwrap();
        assert_eq!(policies.kernel.writes, 0);
        policies.kernel.installed.get_mut(&spec.id).unwrap().config = None;
        policies.reconcile().unwrap();
        assert_eq!(
            policies.kernel.installed[&spec.id].handle.index,
            replacement
        );
        policies.flush_policies().unwrap();
        assert!(policies.kernel.installed.is_empty());
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

    #[test]
    fn empty_desires_retry_failed_deletions_from_inventory() {
        let (id, data) = fixture();
        let key = PolicyKey::new(&id).unwrap();
        let mut foreign = id.clone();
        foreign.if_id = 99;
        let foreign = PolicySpec::new(&foreign, &data).unwrap();
        let mut kernel = MemoryKernel::default();
        kernel.insert(foreign.clone());
        let mut policies = Policies::new(kernel);
        policies.add_policy(id.clone(), data.clone()).unwrap();
        let failed = policies.kernel.installed[&key].handle.index;
        policies.kernel.reject_delete.insert(failed);
        policies.kernel.installed.get_mut(&key).unwrap().config = None;
        let mut missing = id.clone();
        missing.if_id = 42;
        policies.add_policy(missing.clone(), data).unwrap();
        policies
            .kernel
            .installed
            .remove(&PolicyKey::new(&missing).unwrap());
        policies.port_bypass(libc::AF_INET as u16, 13000).unwrap();
        policies.port_bypass(libc::AF_INET6 as u16, 13000).unwrap();
        let writes = policies.kernel.writes;
        policies.clear();
        assert!(policies.policies.is_empty() && policies.bypasses.is_empty());
        assert_eq!(
            policies.reconcile().unwrap_err().raw_os_error(),
            Some(libc::EIO)
        );
        assert_eq!(policies.kernel.installed.len(), 1);
        assert_eq!(policies.kernel.installed[&key].handle.index, failed);
        assert_eq!(
            policies.query_policy(&id).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        policies.kernel.reject_delete.clear();
        policies.reconcile().unwrap();
        policies.reconcile().unwrap();
        assert!(policies.kernel.installed.is_empty());
        assert_eq!(
            policies.kernel.writes, writes,
            "cleanup must never recreate policies"
        );
    }

    #[test]
    fn inventory_prunes_unidentified_duplicates_and_controller_restart_leftovers() {
        let (id, data) = fixture();
        let key = PolicyKey::new(&id).unwrap();
        let mut policies = Policies::new(MemoryKernel::default());
        policies.add_policy(id, data).unwrap();
        let original = policies.kernel.installed[&key].handle.index;
        let mut duplicate_key = key.clone();
        duplicate_key.if_id = 99;
        let mut duplicate = policies.kernel.installed[&key].clone();
        duplicate.handle.index = 98;
        duplicate.config = None;
        policies
            .kernel
            .installed
            .insert(duplicate_key.clone(), duplicate);
        duplicate_key.if_id = 100;
        let mut unidentified = policies.kernel.installed[&key].clone();
        unidentified.handle.index = 99;
        unidentified.handle.id = None;
        policies
            .kernel
            .installed
            .insert(duplicate_key, unidentified);
        policies.reconcile().unwrap();
        assert_eq!(policies.kernel.installed.len(), 1);
        assert_eq!(policies.kernel.installed[&key].handle.index, original);
        assert_eq!(policies.kernel.writes, 1);
        // The next controller has no cached handles or desired state. It can
        // still retire every leftover supplied by the backend's inventory.
        let mut restarted = Policies::new(policies.kernel);
        restarted.reconcile().unwrap();
        assert!(restarted.kernel.installed.is_empty());
    }

    #[test]
    fn flush_preserves_bypasses_and_retries_cleanup_without_restoring_tunnels() {
        let (id, data) = fixture();
        let key = PolicyKey::new(&id).unwrap();
        let mut policies = Policies::new(MemoryKernel::default());
        policies.add_policy(id, data).unwrap();
        policies.port_bypass(libc::AF_INET as u16, 13000).unwrap();
        let failed = policies.kernel.installed[&key].handle.index;
        policies.kernel.reject_delete.insert(failed);
        assert!(policies.flush_policies().is_err());
        assert!(!policies.has_tunnel_policies());
        policies.kernel.reject_delete.clear();
        policies.reconcile().unwrap();
        assert_eq!(policies.kernel.installed.len(), 2);
        assert!(policies.kernel.installed.keys().all(|key| key.if_id == 0));
    }
}
