// SPDX-License-Identifier: GPL-2.0-or-later
//! SA-owned tunnel interface lifecycle and reconciliation, independent of the
//! device API. The caller serializes this controller with SA ownership changes.
use std::{
    collections::{HashMap, HashSet},
    io,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceSpec {
    pub id: u32,
    pub name: String,
    pub mtu: u32,
    pub master: Option<String>,
    pub up: bool,
    pub multicast: bool,
}

#[derive(Clone, Debug)]
pub struct ObservedInterface<H> {
    pub handle: H,
    pub config: InterfaceSpec,
}

/// CRUD for tunnel interfaces. Handles identify objects independently of their
/// mutable settings; listing returns normalized configuration, not device wire
/// messages. Implementations validate handles before modifying an object.
pub trait InterfaceKernel: Send {
    type Handle: Clone + Eq;

    fn list(&mut self) -> io::Result<Vec<ObservedInterface<Self::Handle>>>;
    /// Create only: an existing interface must not be adopted or replaced.
    fn create(&mut self, spec: &InterfaceSpec) -> io::Result<Self::Handle>;
    fn update(&mut self, handle: &Self::Handle, spec: &InterfaceSpec) -> io::Result<()>;
    /// An already absent object counts as successfully deleted. A replacement
    /// object that does not match the handle must be left untouched.
    fn delete(&mut self, handle: &Self::Handle) -> io::Result<()>;
}

pub struct Interfaces<K: InterfaceKernel> {
    kernel: K,
    owned: HashMap<u32, K::Handle>,
    prefix: String,
    master: Option<String>,
    mtu: u32,
}

impl<K: InterfaceKernel> Interfaces<K> {
    pub fn new(kernel: K, prefix: String, master: Option<String>, mtu: u32) -> Self {
        Self {
            kernel,
            owned: HashMap::new(),
            prefix,
            master,
            mtu,
        }
    }

    fn spec(&self, id: u32) -> InterfaceSpec {
        InterfaceSpec {
            id,
            name: format!("{}{:08x}", self.prefix, id),
            mtu: self.mtu,
            master: self.master.clone(),
            up: true,
            multicast: true,
        }
    }

    fn repair(&mut self, id: u32, observed: &[ObservedInterface<K::Handle>]) -> io::Result<()> {
        let spec = self.spec(id);
        if let Some(handle) = self.owned.get(&id) {
            if let Some(current) = observed.iter().find(|entry| &entry.handle == handle) {
                if current.config != spec {
                    self.kernel.update(handle, &spec)?;
                }
                return Ok(());
            }
        }
        if observed
            .iter()
            .any(|entry| entry.config.id == id || entry.config.name == spec.name)
        {
            return Err(io::Error::from_raw_os_error(libc::EEXIST));
        }
        let handle = self.kernel.create(&spec)?;
        self.owned.insert(id, handle);
        Ok(())
    }

    /// Prepare an interface before installing an SA. If installation fails,
    /// remove_unused() rolls this temporary ownership back.
    pub fn ensure(&mut self, id: u32) -> io::Result<()> {
        let observed = self.kernel.list()?;
        self.repair(id, &observed)
    }

    /// Immediate cleanup after SA deletion, hard expiry or failed installation.
    /// This also runs after session loss, without repairing retained interfaces.
    pub fn remove_unused(&mut self, desired: &HashSet<u32>) -> io::Result<()> {
        let unused: Vec<_> = self
            .owned
            .keys()
            .filter(|id| !desired.contains(id))
            .copied()
            .collect();
        let mut first_error = None;
        for id in unused {
            match self.kernel.delete(&self.owned[&id]) {
                Ok(()) => {
                    self.owned.remove(&id);
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Desired IDs come from the current SA ownership set, not from observed
    /// kernel SAs or policy references. One listing serves the entire pass.
    pub fn reconcile(&mut self, desired: &HashSet<u32>) -> io::Result<()> {
        let mut first_error = self.remove_unused(desired).err();
        if !desired.is_empty() {
            let observed = self.kernel.list()?;
            for id in desired {
                if let Err(error) = self.repair(*id, &observed) {
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemoryKernel {
        objects: Vec<ObservedInterface<u64>>,
        next: u64,
        writes: usize,
        reject: HashSet<u32>,
    }

    impl InterfaceKernel for MemoryKernel {
        type Handle = u64;

        fn list(&mut self) -> io::Result<Vec<ObservedInterface<u64>>> {
            Ok(self.objects.clone())
        }
        fn create(&mut self, spec: &InterfaceSpec) -> io::Result<u64> {
            if self.reject.contains(&spec.id) {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            if self
                .objects
                .iter()
                .any(|entry| entry.config.name == spec.name || entry.config.id == spec.id)
            {
                return Err(io::Error::from_raw_os_error(libc::EEXIST));
            }
            self.next += 1;
            self.writes += 1;
            self.objects.push(ObservedInterface {
                handle: self.next,
                config: spec.clone(),
            });
            Ok(self.next)
        }
        fn update(&mut self, handle: &u64, spec: &InterfaceSpec) -> io::Result<()> {
            if self.reject.contains(&spec.id) {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            let entry = self
                .objects
                .iter_mut()
                .find(|entry| entry.handle == *handle)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::ESTALE))?;
            entry.config = spec.clone();
            self.writes += 1;
            Ok(())
        }
        fn delete(&mut self, handle: &u64) -> io::Result<()> {
            self.objects.retain(|entry| entry.handle != *handle);
            Ok(())
        }
    }

    fn controller() -> Interfaces<MemoryKernel> {
        Interfaces::new(
            MemoryKernel::default(),
            "ranet".into(),
            Some("gravity".into()),
            1400,
        )
    }

    #[test]
    fn repairs_configuration_and_absence_without_adopting_replacements() {
        let mut interfaces = controller();
        let desired = HashSet::from([41]);
        interfaces.ensure(41).unwrap();
        let original = interfaces.owned[&41];
        let spec = interfaces.spec(41);
        let entry = &mut interfaces.kernel.objects[0];
        entry.config.mtu = 1280;
        entry.config.master = None;
        entry.config.up = false;
        entry.config.multicast = false;
        entry.config.name = "renamed".into();
        interfaces.reconcile(&desired).unwrap();
        assert_eq!(interfaces.kernel.objects[0].config, spec);
        assert_eq!(interfaces.owned[&41], original);
        let writes = interfaces.kernel.writes;
        interfaces.reconcile(&desired).unwrap();
        assert_eq!(
            interfaces.kernel.writes, writes,
            "unchanged interfaces must not be rewritten"
        );

        interfaces.kernel.objects.clear();
        interfaces.reconcile(&desired).unwrap();
        assert_ne!(interfaces.owned[&41], original);
        assert_eq!(interfaces.kernel.objects[0].config, spec);

        // A different object with the same configuration is not ours.
        interfaces.kernel.objects[0].handle = 999;
        assert_eq!(
            interfaces.reconcile(&desired).unwrap_err().raw_os_error(),
            Some(libc::EEXIST)
        );
        assert_ne!(interfaces.owned[&41], 999);
        interfaces.reconcile(&HashSet::new()).unwrap();
        assert!(interfaces.owned.is_empty());
        assert_eq!(interfaces.kernel.objects[0].handle, 999);
    }

    #[test]
    fn sharing_rollback_and_teardown_follow_current_sa_ownership() {
        let mut interfaces = controller();
        interfaces.ensure(41).unwrap();
        let handle = interfaces.owned[&41];
        interfaces.ensure(41).unwrap();
        assert_eq!(interfaces.owned[&41], handle);
        assert_eq!(interfaces.kernel.writes, 1);

        interfaces.kernel.reject.insert(42);
        assert!(interfaces.ensure(42).is_err());
        assert!(!interfaces.owned.contains_key(&42));
        interfaces.ensure(43).unwrap();
        interfaces.remove_unused(&HashSet::from([41])).unwrap();
        assert_eq!(
            interfaces.owned.len(),
            1,
            "failed SA installation must release its interface"
        );

        // Deletion of the last SA wins even if the interface was also deleted
        // externally and a repair was pending.
        interfaces.kernel.objects.clear();
        interfaces.reconcile(&HashSet::new()).unwrap();
        interfaces.reconcile(&HashSet::new()).unwrap();
        assert!(interfaces.owned.is_empty());
        assert!(interfaces.kernel.objects.is_empty());
    }

    #[test]
    fn one_failed_repair_does_not_block_other_interfaces() {
        let mut interfaces = controller();
        interfaces.ensure(41).unwrap();
        interfaces.ensure(42).unwrap();
        interfaces.kernel.objects[0].config.mtu = 1280;
        interfaces.kernel.objects.pop();
        interfaces.kernel.reject.insert(41);
        assert_eq!(
            interfaces
                .reconcile(&HashSet::from([41, 42]))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EIO)
        );
        assert!(interfaces
            .kernel
            .objects
            .iter()
            .any(|entry| entry.config == interfaces.spec(42)));
        interfaces.kernel.reject.clear();
        interfaces.reconcile(&HashSet::from([41, 42])).unwrap();
        assert!(interfaces
            .kernel
            .objects
            .iter()
            .any(|entry| entry.config == interfaces.spec(41)));
    }
}
