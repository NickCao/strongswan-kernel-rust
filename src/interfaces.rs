// SPDX-License-Identifier: GPL-2.0-or-later
//! Tunnel interface lifecycle and reconciliation, independent of the device API.
//! The caller serializes this controller with SA and policy ownership changes.
use std::{collections::HashSet, fmt, io, str::FromStr};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceConfig {
    pub if_id: u32,
    pub mtu: u32,
    pub master: Option<String>,
    pub up: bool,
    pub multicast: bool,
}

/// Caller-assigned identity. Backends may encode it for discovery, but must not
/// interpret it as native configuration (in particular, as an XFRM if_id).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InterfaceId(u32);

impl fmt::Display for InterfaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}
impl FromStr for InterfaceId {
    type Err = io::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let id = Self(u32::from_str_radix(value, 16).map_err(|_| crate::error::invalid())?);
        if value != id.to_string() {
            return Err(crate::error::invalid());
        }
        Ok(id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceSpec {
    pub id: InterfaceId,
    pub config: InterfaceConfig,
}

#[derive(Clone, Debug)]
pub struct ObservedInterface<H> {
    pub handle: H,
    /// None when the native configuration cannot be represented by our model.
    /// A known desired ID is still repaired through update().
    pub config: Option<InterfaceConfig>,
}

/// Logical identity captured by list(), read from the snapshot without I/O.
/// All managed configuration is exposed through ObservedInterface::config.
pub trait InterfaceHandle {
    /// The caller-supplied logical ID, or None for an unidentified owned object.
    fn id(&self) -> Option<InterfaceId>;
}

/// CRUD for tunnel interfaces. Handles identify objects independently of their
/// mutable settings. Listing returns only backend-owned objects, including
/// leftovers discovered after restart. Backends own naming and ownership rules
/// and define the native key used to target mutations.
pub trait InterfaceKernel: Send {
    type Handle: InterfaceHandle + Send + Sync;

    fn list(
        &mut self,
    ) -> impl std::future::Future<Output = io::Result<Vec<ObservedInterface<Self::Handle>>>> + Send;
    /// Create only: an existing object must not be replaced. Existing owned
    /// interfaces are discovered via list() and updated by the controller.
    fn create(
        &mut self,
        spec: &InterfaceSpec,
    ) -> impl std::future::Future<Output = io::Result<Self::Handle>> + Send;
    /// Achieve this configuration for the object identified by the handle.
    /// The backend chooses in-place repair or replacement. Callers must list
    /// again before reusing a handle after a potentially replacing update.
    fn update(
        &mut self,
        handle: &Self::Handle,
        spec: &InterfaceSpec,
    ) -> impl std::future::Future<Output = io::Result<()>> + Send;
    /// An already absent object counts as successfully deleted. The handle's
    /// native key determines the object targeted by this operation.
    fn delete(
        &mut self,
        handle: &Self::Handle,
    ) -> impl std::future::Future<Output = io::Result<()>> + Send;
}

pub struct Interfaces<K: InterfaceKernel> {
    kernel: K,
    master: Option<String>,
    mtu: u32,
}

impl<K: InterfaceKernel> Interfaces<K> {
    pub fn new(kernel: K, master: Option<String>, mtu: u32) -> Self {
        Self {
            kernel,
            master,
            mtu,
        }
    }

    fn spec(&self, if_id: u32) -> InterfaceSpec {
        InterfaceSpec {
            // The caller uses the SA/policy binding as its logical key.
            // Device backends receive the key and native configuration separately.
            id: InterfaceId(if_id),
            config: InterfaceConfig {
                if_id,
                mtu: self.mtu,
                master: self.master.clone(),
                up: true,
                multicast: true,
            },
        }
    }

    async fn repair(
        &mut self,
        if_id: u32,
        observed: &[ObservedInterface<K::Handle>],
    ) -> io::Result<()> {
        let spec = self.spec(if_id);
        if let Some(current) = observed
            .iter()
            .find(|entry| entry.handle.id() == Some(spec.id))
        {
            if current.config.as_ref() != Some(&spec.config) {
                self.kernel.update(&current.handle, &spec).await?;
            }
            return Ok(());
        }
        self.kernel.create(&spec).await?;
        Ok(())
    }

    async fn prune(
        &mut self,
        observed: &[ObservedInterface<K::Handle>],
        keep: impl Fn(InterfaceId) -> bool,
    ) -> io::Result<()> {
        let mut first_error = None;
        let mut retained = HashSet::new();
        for entry in observed {
            if entry
                .handle
                .id()
                .is_none_or(|id| !keep(id) || !retained.insert(id))
            {
                if let Err(error) = self.kernel.delete(&entry.handle).await {
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn inventory(&mut self) -> io::Result<Vec<ObservedInterface<K::Handle>>> {
        let mut observed = self.kernel.list().await?;
        // If multiple owned objects claim an ID, retain a representable one
        // before attempting a backend repair of an unrepresentable duplicate.
        observed.sort_by_key(|entry| entry.config.is_none());
        Ok(observed)
    }

    /// Prepare an interface before installing an SA or policy. If installation fails,
    /// remove_unused() rolls this temporary ownership back.
    pub async fn ensure(&mut self, id: u32) -> io::Result<()> {
        let observed = self.inventory().await?;
        let cleanup = self.prune(&observed, |_| true).await;
        let repair = self.repair(id, &observed).await;
        cleanup.and(repair)
    }

    /// Immediate cleanup after ownership removal or failed installation.
    /// This also runs after session loss, without repairing retained interfaces.
    pub async fn remove_unused(&mut self, desired: &HashSet<u32>) -> io::Result<()> {
        let observed = self.inventory().await?;
        let desired: HashSet<_> = desired.iter().map(|id| InterfaceId(*id)).collect();
        self.prune(&observed, |id| desired.contains(&id)).await
    }

    /// Desired IDs come from current SA and policy ownership, independently of
    /// kernel inventory. One listing serves the entire pass.
    pub async fn reconcile(&mut self, desired: &HashSet<u32>) -> io::Result<()> {
        let observed = self.inventory().await?;
        let ids: HashSet<_> = desired.iter().map(|id| InterfaceId(*id)).collect();
        let mut first_error = self.prune(&observed, |id| ids.contains(&id)).await.err();
        for id in desired {
            if let Err(error) = self.repair(*id, &observed).await {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug)]
    struct MemoryHandle {
        identity: u64,
        id: Option<InterfaceId>,
        name: String,
    }
    impl InterfaceHandle for MemoryHandle {
        fn id(&self) -> Option<InterfaceId> {
            self.id
        }
    }
    #[derive(Default)]
    struct MemoryKernel {
        objects: Vec<ObservedInterface<MemoryHandle>>,
        unowned: HashSet<u64>,
        next: u64,
        writes: usize,
        creates: usize,
        updates: usize,
        reject: HashSet<u32>,
        reject_delete: HashSet<u64>,
    }
    impl MemoryKernel {
        fn name(id: InterfaceId) -> String {
            format!("memory-{id}")
        }
    }
    impl InterfaceKernel for MemoryKernel {
        type Handle = MemoryHandle;
        async fn list(&mut self) -> io::Result<Vec<ObservedInterface<MemoryHandle>>> {
            Ok(self
                .objects
                .iter()
                .filter(|entry| !self.unowned.contains(&entry.handle.identity))
                .cloned()
                .collect())
        }
        async fn create(&mut self, spec: &InterfaceSpec) -> io::Result<MemoryHandle> {
            if self.reject.contains(&spec.config.if_id) {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            let name = Self::name(spec.id);
            if self
                .objects
                .iter()
                .any(|entry| entry.handle.name == name || entry.handle.id == Some(spec.id))
            {
                return Err(io::Error::from_raw_os_error(libc::EEXIST));
            }
            self.next += 1;
            self.writes += 1;
            self.creates += 1;
            let handle = MemoryHandle {
                identity: self.next,
                id: Some(spec.id),
                name,
            };
            self.objects.push(ObservedInterface {
                handle: handle.clone(),
                config: Some(spec.config.clone()),
            });
            Ok(handle)
        }
        async fn update(&mut self, handle: &MemoryHandle, spec: &InterfaceSpec) -> io::Result<()> {
            self.updates += 1;
            if self.reject.contains(&spec.config.if_id) || self.unowned.contains(&handle.identity) {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            let entry = self
                .objects
                .iter_mut()
                .find(|entry| entry.handle.identity == handle.identity)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::ESTALE))?;
            assert_eq!(entry.handle.id(), Some(spec.id));
            entry.config = Some(spec.config.clone());
            entry.handle.name = Self::name(spec.id);
            self.writes += 1;
            Ok(())
        }
        async fn delete(&mut self, handle: &MemoryHandle) -> io::Result<()> {
            if self.unowned.contains(&handle.identity) {
                return Ok(());
            }
            if self.reject_delete.contains(&handle.identity) {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            self.objects
                .retain(|entry| entry.handle.identity != handle.identity);
            Ok(())
        }
    }
    fn controller() -> Interfaces<MemoryKernel> {
        Interfaces::new(MemoryKernel::default(), Some("gravity".into()), 1400)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn logical_identity_is_independent_of_native_configuration() {
        let mut kernel = MemoryKernel::default();
        let mut spec = controller().spec(41);
        spec.id = InterfaceId(7);
        let handle = kernel.create(&spec).await.unwrap();
        assert_eq!(handle.id(), Some(InterfaceId(7)));
        assert_eq!(kernel.objects[0].config.as_ref().unwrap().if_id, 41);
        spec.config.if_id = 42;
        kernel.update(&handle, &spec).await.unwrap();
        assert_eq!(kernel.objects[0].handle.id(), Some(InterfaceId(7)));
        assert_eq!(kernel.objects[0].config.as_ref().unwrap().if_id, 42);
        assert_eq!(kernel.objects[0].handle.name, "memory-00000007");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn repairs_configuration_without_updating_unchanged_interfaces() {
        let mut interfaces = controller();
        let desired = HashSet::from([41]);
        interfaces.ensure(41).await.unwrap();
        let original = interfaces.kernel.objects[0].handle.identity;
        let spec = interfaces.spec(41);
        let config = interfaces.kernel.objects[0].config.as_mut().unwrap();
        config.mtu = 1280;
        config.master = None;
        config.up = false;
        config.multicast = false;
        interfaces.reconcile(&desired).await.unwrap();
        assert_eq!(
            interfaces.kernel.objects[0].config.as_ref(),
            Some(&spec.config)
        );
        assert_eq!(interfaces.kernel.objects[0].handle.identity, original);
        let updates = interfaces.kernel.updates;
        interfaces.reconcile(&desired).await.unwrap();
        assert_eq!(
            interfaces.kernel.updates, updates,
            "unchanged interfaces must not call update"
        );
        interfaces.kernel.objects.clear();
        interfaces.reconcile(&desired).await.unwrap();
        assert_ne!(interfaces.kernel.objects[0].handle.identity, original);
        // The backend releases ownership; a conflicting unowned object stays.
        interfaces.kernel.objects[0].handle.identity = 999;
        interfaces.kernel.unowned.insert(999);
        assert_eq!(
            interfaces
                .reconcile(&desired)
                .await
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EEXIST)
        );
        interfaces.reconcile(&HashSet::new()).await.unwrap();
        assert_eq!(interfaces.kernel.objects.len(), 1);
        assert_eq!(interfaces.kernel.objects[0].handle.identity, 999);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sharing_rollback_and_teardown_follow_current_sa_ownership() {
        let mut interfaces = controller();
        interfaces.ensure(41).await.unwrap();
        let handle = interfaces.kernel.objects[0].handle.identity;
        interfaces.ensure(41).await.unwrap();
        assert_eq!(interfaces.kernel.objects[0].handle.identity, handle);
        assert_eq!(interfaces.kernel.writes, 1);
        interfaces.kernel.reject.insert(42);
        assert!(interfaces.ensure(42).await.is_err());
        assert_eq!(interfaces.kernel.objects.len(), 1);
        interfaces.ensure(43).await.unwrap();
        interfaces
            .remove_unused(&HashSet::from([41]))
            .await
            .unwrap();
        assert_eq!(
            interfaces.kernel.objects.len(),
            1,
            "failed SA installation must release its interface"
        );
        interfaces.kernel.objects.clear();
        interfaces.reconcile(&HashSet::new()).await.unwrap();
        interfaces.reconcile(&HashSet::new()).await.unwrap();
        assert!(interfaces.kernel.objects.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn one_failed_repair_does_not_block_other_interfaces() {
        let mut interfaces = controller();
        interfaces.ensure(41).await.unwrap();
        interfaces.ensure(42).await.unwrap();
        interfaces.kernel.objects[0].config.as_mut().unwrap().mtu = 1280;
        interfaces.kernel.objects.pop();
        interfaces.kernel.reject.insert(41);
        assert_eq!(
            interfaces
                .reconcile(&HashSet::from([41, 42]))
                .await
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EIO)
        );
        assert!(interfaces
            .kernel
            .objects
            .iter()
            .any(|entry| entry.config.as_ref() == Some(&interfaces.spec(42).config)));
        interfaces.kernel.reject.clear();
        interfaces
            .reconcile(&HashSet::from([41, 42]))
            .await
            .unwrap();
        assert!(interfaces
            .kernel
            .objects
            .iter()
            .any(|entry| entry.config.as_ref() == Some(&interfaces.spec(41).config)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn empty_desired_set_retries_deletions_and_preserves_foreign_interfaces() {
        let mut interfaces = controller();
        interfaces.ensure(41).await.unwrap();
        interfaces.ensure(42).await.unwrap();
        interfaces.kernel.objects.push(ObservedInterface {
            handle: MemoryHandle {
                identity: 999,
                id: Some(InterfaceId(99)),
                name: "foreign".into(),
            },
            config: Some(interfaces.spec(99).config),
        });
        interfaces.kernel.unowned.insert(999);
        let failed = interfaces.kernel.objects[0].handle.identity;
        interfaces.kernel.reject_delete.insert(failed);
        assert!(interfaces.reconcile(&HashSet::new()).await.is_err());
        assert_eq!(interfaces.kernel.objects.len(), 2);
        let writes = interfaces.kernel.writes;
        interfaces.kernel.reject_delete.clear();
        interfaces.reconcile(&HashSet::new()).await.unwrap();
        interfaces.reconcile(&HashSet::new()).await.unwrap();
        assert_eq!(interfaces.kernel.objects.len(), 1);
        assert_eq!(interfaces.kernel.objects[0].handle.identity, 999);
        assert_eq!(interfaces.kernel.writes, writes);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn known_ids_with_unrepresentable_config_are_updated_and_survive_controller_restart() {
        let mut interfaces = controller();
        interfaces.kernel.objects.push(ObservedInterface {
            handle: MemoryHandle {
                identity: 1,
                id: Some(InterfaceId(41)),
                name: "memory-00000029".into(),
            },
            config: None,
        });
        interfaces.kernel.next = 1;
        interfaces.ensure(41).await.unwrap();
        assert_eq!(interfaces.kernel.objects.len(), 1);
        assert_eq!(interfaces.kernel.objects[0].handle.identity, 1);
        assert_eq!(interfaces.kernel.updates, 1);
        assert_eq!(
            interfaces.kernel.creates, 0,
            "the backend chooses how to repair"
        );
        let Interfaces {
            kernel,
            master,
            mtu,
        } = interfaces;
        let mut restarted = Interfaces::new(kernel, master, mtu);
        restarted.reconcile(&HashSet::from([41])).await.unwrap();
        assert_eq!(
            restarted.kernel.writes, 1,
            "owned inventory must be reused after restart"
        );
        restarted.reconcile(&HashSet::new()).await.unwrap();
        assert!(restarted.kernel.objects.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unidentified_objects_and_duplicate_ids_are_deleted_without_replacing_the_retained_object(
    ) {
        let mut interfaces = controller();
        interfaces.ensure(41).await.unwrap();
        let original = interfaces.kernel.objects[0].clone();
        let mut duplicate = original.clone();
        duplicate.handle.identity = 98;
        duplicate.config = None;
        interfaces.kernel.objects.insert(0, duplicate);
        interfaces.kernel.objects.push(ObservedInterface {
            handle: MemoryHandle {
                identity: 99,
                id: None,
                name: "unidentified".into(),
            },
            config: None,
        });
        interfaces.reconcile(&HashSet::from([41])).await.unwrap();
        assert_eq!(interfaces.kernel.objects.len(), 1);
        assert_eq!(
            interfaces.kernel.objects[0].handle.identity,
            original.handle.identity
        );
        assert_eq!(interfaces.kernel.updates, 0);
    }
}
