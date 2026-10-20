// SPDX-License-Identifier: GPL-2.0-or-later
//! Desired policy ownership and reconciliation, independent of the device API.
use crate::{error::invalid, model::*};
use std::{collections::HashMap, hash::Hash, io};

fn missing() -> io::Error {
    io::Error::from_raw_os_error(libc::ENOENT)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyStatus {
    Missing,
    Changed,
    Matching,
}

/// Device operations used by the policy controller. Implementations translate
/// semantic policy requests and compare configuration in their native inventory.
/// Keys identify policies independently of priorities or SA templates.
pub trait PolicyKernel: Send {
    type Key: Clone + Eq + Hash;
    type Inventory;
    fn key(id: &PolicyId) -> io::Result<Self::Key>;
    fn priority(id: &PolicyId, data: &PolicyData) -> io::Result<(u32, u32)>;
    fn list_policies(&mut self) -> io::Result<Self::Inventory>;
    fn policy_status(
        &self,
        inventory: &Self::Inventory,
        id: &PolicyId,
        data: &PolicyData,
    ) -> io::Result<PolicyStatus>;
    /// replace=false must refuse an existing policy; replace=true may upsert.
    fn write_policy(&mut self, id: &PolicyId, data: &PolicyData, replace: bool) -> io::Result<()>;
    /// Deleting an already absent policy succeeds.
    fn delete_policy(&mut self, id: &PolicyId) -> io::Result<()>;
    /// CLOCK_MONOTONIC seconds, or zero if unused or unavailable.
    fn query_policy(&mut self, id: &PolicyId) -> io::Result<u64>;
}

struct PolicyState {
    id: PolicyId,
    used_by: Vec<PolicyData>,
}

pub struct Policies<K: PolicyKernel> {
    kernel: K,
    policies: HashMap<K::Key, PolicyState>,
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
    pub fn add_policy(&mut self, id: PolicyId, data: PolicyData) -> io::Result<()> {
        let key = K::key(&id)?;
        let current = self.policies.get(&key);
        let mut uses = current.map(|p| p.used_by.clone()).unwrap_or_default();
        let priority = K::priority(&id, &data)?;
        let mut pos = uses.len();
        for (index, existing_data) in uses.iter().enumerate() {
            let existing = K::priority(&id, existing_data)?;
            if existing > priority
                || (existing == priority && (existing_data.reqid == 0 || data.reqid != 0))
            {
                pos = index;
                break;
            }
        }
        if pos == 0 {
            self.kernel.write_policy(&id, &data, current.is_some())?;
        }
        uses.insert(pos, data);
        self.policies.insert(key, PolicyState { id, used_by: uses });
        Ok(())
    }
    pub fn delete_policy(&mut self, id: &PolicyId, data: &PolicyData) -> io::Result<()> {
        let key = K::key(id)?;
        let state = self.policies.get(&key).ok_or_else(missing)?;
        let mut uses = state.used_by.clone();
        let pos = uses.iter().position(|p| p == data).ok_or_else(missing)?;
        uses.remove(pos);
        if uses.is_empty() {
            self.kernel.delete_policy(&state.id)?;
            self.policies.remove(&key);
        } else {
            if pos == 0 {
                self.kernel.write_policy(&state.id, &uses[0], true)?;
            }
            self.policies.get_mut(&key).unwrap().used_by = uses;
        }
        Ok(())
    }
    pub fn query_policy(&mut self, id: &PolicyId) -> io::Result<u64> {
        if !self.policies.contains_key(&K::key(id)?) {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        self.kernel.query_policy(id)
    }
    pub fn contains_reqid(&self, if_id: u32, reqid: u32) -> bool {
        self.policies.values().any(|policy| {
            policy.id.if_id == if_id && policy.used_by.iter().any(|data| data.reqid == reqid)
        })
    }
    /// The caller holds the same lock as add/delete throughout inventory and
    /// repair, so no stale snapshot of desired policies can outlive a deletion.
    pub fn reconcile(&mut self) -> io::Result<()> {
        if self.policies.is_empty() {
            return Ok(());
        }
        let inventory = self.kernel.list_policies()?;
        let mut first_error = None;
        for state in self.policies.values() {
            let data = &state.used_by[0];
            let result = match self.kernel.policy_status(&inventory, &state.id, data) {
                Ok(PolicyStatus::Matching) => Ok(()),
                Ok(status) => {
                    self.kernel
                        .write_policy(&state.id, data, status == PolicyStatus::Changed)
                }
                Err(error) => Err(error),
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
            .iter()
            .filter(|(_, p)| p.id.if_id != 0)
            .map(|(k, _)| k.clone())
            .collect();
        for key in keys {
            let state = &self.policies[&key];
            self.kernel.delete_policy(&state.id)?;
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
        self.policies.values().any(|p| p.id.if_id != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemoryKernel {
        installed: HashMap<PolicyId, PolicyData>,
        writes: usize,
        reject_write: bool,
    }
    impl PolicyKernel for MemoryKernel {
        type Key = PolicyId;
        type Inventory = HashMap<PolicyId, PolicyData>;
        fn key(id: &PolicyId) -> io::Result<Self::Key> {
            Ok(id.clone())
        }
        fn priority(_: &PolicyId, data: &PolicyData) -> io::Result<(u32, u32)> {
            Ok((data.manual_prio, data.manual_prio))
        }
        fn list_policies(&mut self) -> io::Result<Self::Inventory> {
            Ok(self.installed.clone())
        }
        fn policy_status(
            &self,
            inventory: &Self::Inventory,
            id: &PolicyId,
            data: &PolicyData,
        ) -> io::Result<PolicyStatus> {
            Ok(match inventory.get(id) {
                None => PolicyStatus::Missing,
                Some(current) if current == data => PolicyStatus::Matching,
                Some(_) => PolicyStatus::Changed,
            })
        }
        fn write_policy(
            &mut self,
            id: &PolicyId,
            data: &PolicyData,
            replace: bool,
        ) -> io::Result<()> {
            if self.reject_write {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            if !replace && self.installed.contains_key(id) {
                return Err(io::Error::from_raw_os_error(libc::EEXIST));
            }
            self.installed.insert(id.clone(), data.clone());
            self.writes += 1;
            Ok(())
        }
        fn delete_policy(&mut self, id: &PolicyId) -> io::Result<()> {
            self.installed.remove(id);
            Ok(())
        }
        fn query_policy(&mut self, _: &PolicyId) -> io::Result<u64> {
            Ok(0)
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
        let mut new = old.clone();
        new.esp = Some(0x10204);
        let mut foreign = id.clone();
        foreign.if_id = 99;
        let mut kernel = MemoryKernel::default();
        kernel.installed.insert(foreign.clone(), old.clone());
        let mut policies = Policies::new(kernel);
        policies.add_policy(id.clone(), old.clone()).unwrap();
        policies.add_policy(id.clone(), new.clone()).unwrap();
        policies.kernel.installed.insert(id.clone(), old.clone());
        policies.reconcile().unwrap();
        assert_eq!(policies.kernel.installed[&id], new);
        policies.kernel.installed.remove(&id);
        policies.reconcile().unwrap();
        assert_eq!(policies.kernel.installed[&id], new);
        let writes = policies.kernel.writes;
        policies.reconcile().unwrap();
        assert_eq!(
            policies.kernel.writes, writes,
            "matching policies must not be rewritten"
        );
        policies.delete_policy(&id, &new).unwrap();
        assert_eq!(policies.kernel.installed[&id], old);
        policies.kernel.installed.remove(&id);
        policies.delete_policy(&id, &old).unwrap();
        policies.reconcile().unwrap();
        assert_eq!(policies.kernel.installed.len(), 1);
        assert_eq!(policies.kernel.installed[&foreign], old);
    }
    #[test]
    fn rejected_installs_do_not_become_desired_policies() {
        let (id, data) = fixture();
        let mut policies = Policies::new(MemoryKernel {
            reject_write: true,
            ..Default::default()
        });
        assert!(policies.add_policy(id.clone(), data.clone()).is_err());
        policies.kernel.reject_write = false;
        policies.reconcile().unwrap();
        assert!(policies.kernel.installed.is_empty());
        policies.kernel.installed.insert(id.clone(), data.clone());
        assert_eq!(
            policies
                .add_policy(id.clone(), data.clone())
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EEXIST)
        );
        policies.reconcile().unwrap();
        assert_eq!(
            policies.kernel.writes, 0,
            "foreign policies cannot be adopted"
        );
    }
}
