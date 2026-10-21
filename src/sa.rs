// SPDX-License-Identifier: GPL-2.0-or-later
//! Immutable SA lifecycle. Established SAs are never repaired or recreated:
//! loss or configuration drift retires them and asks the IKE owner to recover.
use crate::model::{Endpoint, SaConfig, SaId};
pub use crate::rpc_api::SaUsage;
use std::{
    collections::{HashMap, HashSet},
    io,
    net::IpAddr,
};

pub fn is_missing(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}
fn missing() -> io::Error {
    io::Error::from_raw_os_error(libc::ENOENT)
}

/// Installation input. Keys are used only for first installation, including
/// completion of a larval reservation; they are never replayed by an audit.
pub struct SaSpec<'a> {
    pub id: &'a SaId,
    pub config: &'a SaConfig,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaState {
    Installed,
    Larval,
    /// A temporary kernel acquisition, before the IKE owner installs an SA.
    /// The kernel owns its timeout; it may not yet have an addressable SPI.
    Acquiring,
}

pub trait SaHandle {
    fn id(&self) -> &SaId;
}

pub struct ObservedSa<H, C> {
    pub handle: H,
    pub state: SaState,
    /// Canonical managed configuration, excluding live sequence numbers,
    /// replay bitmaps, counters, usage timestamps and acquire sequence IDs.
    /// None for reservations/acquisitions and unsupported native configuration.
    pub config: Option<C>,
    /// Installation timestamp, used to detect replacement under the same key.
    /// This is an observation, not a requested lifetime or a unique object ID.
    pub created_at: u64,
    pub usage: SaUsage,
}

/// Stateless device operations. Configuration snapshots normalize native
/// defaults/aliases and must contain only managed, immutable settings. Their
/// representation belongs to the backend; the controller only compares them.
/// There is deliberately no operation to update an established SA.
pub trait SaKernel: Send {
    type Handle: SaHandle;
    type Config: PartialEq;

    fn features(&self) -> u32;
    fn allocate(
        &mut self,
        src: &Endpoint,
        dst: &Endpoint,
        proto: u8,
        min: u32,
        max: u32,
    ) -> io::Result<u32>;
    fn list(&mut self) -> io::Result<Vec<ObservedSa<Self::Handle, Self::Config>>>;
    fn get(&mut self, id: &SaId) -> io::Result<ObservedSa<Self::Handle, Self::Config>>;
    /// First installation only. config.update may complete a known larval
    /// reservation or create it if the reservation expired. An existing
    /// established SA must never be modified, even for a repeated request.
    /// Return the canonical installed configuration after resolving defaults.
    fn create(&mut self, spec: &SaSpec<'_>) -> io::Result<ObservedSa<Self::Handle, Self::Config>>;
    fn delete(&mut self, handle: &Self::Handle) -> io::Result<()>;
    /// Bulk deletion also covers acquisitions without an addressable SPI.
    fn flush(&mut self) -> io::Result<()>;
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Reservation {
    src: IpAddr,
    dst: IpAddr,
    spi: u32,
    proto: u8,
}
impl From<&SaId> for Reservation {
    fn from(id: &SaId) -> Self {
        Self {
            src: id.src.address,
            dst: id.dst.address,
            spi: id.spi,
            proto: id.proto,
        }
    }
}
struct DesiredSa<C> {
    config: C,
    created_at: u64,
}

/// Successful inventory may retire SAs even when deleting a native object
/// fails. Deliver those expiry notifications and retry unwanted-object cleanup
/// on the next pass instead of losing notifications with the cleanup error.
pub struct SaChanges {
    pub expired: Vec<SaId>,
    pub cleanup_error: Option<io::Error>,
}

pub struct Sas<K: SaKernel> {
    kernel: K,
    installed: HashMap<SaId, DesiredSa<K::Config>>,
    reservations: HashSet<Reservation>,
}
impl<K: SaKernel> Sas<K> {
    pub fn new(kernel: K) -> Self {
        Self {
            kernel,
            installed: HashMap::new(),
            reservations: HashSet::new(),
        }
    }
    pub fn features(&self) -> u32 {
        self.kernel.features()
    }
    pub fn ids(&self) -> impl Iterator<Item = &SaId> {
        self.installed.keys()
    }
    pub fn is_empty(&self) -> bool {
        self.installed.is_empty()
    }
    pub fn contains(&self, id: &SaId) -> bool {
        self.installed.contains_key(&id.key())
    }
    pub fn allocate(
        &mut self,
        src: Endpoint,
        dst: Endpoint,
        proto: u8,
        min: u32,
        max: u32,
    ) -> io::Result<u32> {
        let spi = self.kernel.allocate(&src, &dst, proto, min, max)?;
        self.reservations.insert(Reservation {
            src: src.address,
            dst: dst.address,
            spi,
            proto,
        });
        Ok(spi)
    }
    pub fn install(&mut self, id: &SaId, data: &SaConfig) -> io::Result<()> {
        let key = id.key();
        if self.installed.contains_key(&key) {
            return Err(io::Error::from_raw_os_error(libc::EEXIST));
        }
        let reservation = Reservation::from(id);
        if data.update && !self.reservations.contains(&reservation) {
            return Err(missing());
        }
        let current = self.kernel.create(&SaSpec { id, config: data })?;
        let config = current
            .config
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EOPNOTSUPP))?;
        self.installed.insert(
            key,
            DesiredSa {
                config,
                created_at: current.created_at,
            },
        );
        self.reservations.remove(&reservation);
        Ok(())
    }
    pub fn query(&mut self, id: &SaId) -> io::Result<SaUsage> {
        if !self.contains(id) {
            return Err(missing());
        }
        Ok(self.kernel.get(id)?.usage)
    }
    pub fn remove(&mut self, id: &SaId) -> io::Result<()> {
        // Desired state is removed even if native deletion fails. Future
        // inventories retry deletion; neither the SA nor its interface revives.
        self.installed.remove(&id.key());
        self.reservations.remove(&Reservation::from(id));
        match self.kernel.get(id) {
            Ok(current) => self.kernel.delete(&current.handle),
            Err(error) if is_missing(&error) => Ok(()),
            Err(error) => Err(error),
        }
    }
    /// Return whether the event belongs to a currently installed SA. Removing
    /// desired state on hard expiry suppresses a second audit notification.
    pub fn expire(&mut self, id: &SaId, hard: bool) -> bool {
        let key = id.key();
        if hard {
            self.installed.remove(&key).is_some()
        } else {
            self.installed.contains_key(&key)
        }
    }
    pub fn reconcile(&mut self) -> io::Result<SaChanges> {
        // Never interpret a failed, partial or undecodable inventory as loss.
        // The caller holds the installation/deletion lock for this entire pass.
        let inventory = self.kernel.list()?;
        let mut retained = HashSet::new();
        let mut cleanup_error = None;
        for current in inventory {
            let id = current.handle.id().key();
            if let Some(desired) = self.installed.get(&id) {
                if current.state == SaState::Installed
                    && current.config.as_ref() == Some(&desired.config)
                    && current.created_at == desired.created_at
                    && retained.insert(id)
                {
                    continue;
                }
            } else if current.state == SaState::Acquiring
                || (current.state == SaState::Larval
                    && self.reservations.contains(&Reservation::from(&id)))
            {
                continue;
            }
            if let Err(error) = self.kernel.delete(&current.handle) {
                cleanup_error.get_or_insert(error);
            }
        }
        let mut expired = Vec::new();
        self.installed.retain(|id, _| {
            if retained.contains(id) {
                true
            } else {
                expired.push(id.clone());
                false
            }
        });
        Ok(SaChanges {
            expired,
            cleanup_error,
        })
    }
    pub fn clear(&mut self) -> io::Result<()> {
        self.installed.clear();
        self.reservations.clear();
        self.kernel.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Mark;

    #[derive(Clone)]
    struct Handle(SaId);
    impl SaHandle for Handle {
        fn id(&self) -> &SaId {
            &self.0
        }
    }
    #[derive(Default)]
    struct MemoryKernel {
        objects: HashMap<SaId, (Option<u32>, SaState, u64, SaUsage)>,
        creates: usize,
        fail_list: bool,
        fail_delete: bool,
    }
    impl SaKernel for MemoryKernel {
        type Handle = Handle;
        type Config = u32;
        fn features(&self) -> u32 {
            0
        }
        fn allocate(
            &mut self,
            src: &Endpoint,
            dst: &Endpoint,
            proto: u8,
            min: u32,
            _: u32,
        ) -> io::Result<u32> {
            let id = SaId {
                src: *src,
                dst: *dst,
                spi: min,
                proto,
                mark: Mark::default(),
                if_id: 0,
            }
            .key();
            self.objects
                .insert(id, (None, SaState::Larval, 1, SaUsage::default()));
            Ok(min)
        }
        fn list(&mut self) -> io::Result<Vec<ObservedSa<Handle, u32>>> {
            if self.fail_list {
                return Err(io::Error::from_raw_os_error(libc::EINTR));
            }
            Ok(self
                .objects
                .iter()
                .map(|(id, (config, state, created_at, usage))| ObservedSa {
                    handle: Handle(id.clone()),
                    config: *config,
                    state: *state,
                    created_at: *created_at,
                    usage: *usage,
                })
                .collect())
        }
        fn get(&mut self, id: &SaId) -> io::Result<ObservedSa<Handle, u32>> {
            self.list()?
                .into_iter()
                .find(|current| current.handle.id() == &id.key())
                .ok_or_else(missing)
        }
        fn create(&mut self, spec: &SaSpec<'_>) -> io::Result<ObservedSa<Handle, u32>> {
            self.creates += 1;
            self.objects.retain(|id, (_, state, _, _)| {
                !(*state == SaState::Larval && Reservation::from(id) == Reservation::from(spec.id))
            });
            self.objects.insert(
                spec.id.key(),
                (
                    Some(spec.config.reqid),
                    SaState::Installed,
                    10,
                    SaUsage::default(),
                ),
            );
            self.get(spec.id)
        }
        fn delete(&mut self, handle: &Handle) -> io::Result<()> {
            if self.fail_delete {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            self.objects.remove(handle.id());
            Ok(())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.objects.clear();
            Ok(())
        }
    }
    fn fixture() -> (SaId, SaConfig) {
        (
            SaId {
                src: Endpoint::new("192.0.2.1".parse().unwrap(), 13000),
                dst: Endpoint::new("192.0.2.2".parse().unwrap(), 13000),
                spi: 0x10203,
                proto: 50,
                mark: Mark::default(),
                if_id: 41,
            },
            SaConfig {
                reqid: 42,
                acquire_sequence: 0,
                mode: 2,
                src_selectors: None,
                dst_selectors: None,
                interface: None,
                encryption: crate::rpc_api::Algorithm {
                    id: 20,
                    name: String::new(),
                    key: vec![0; 20],
                },
                integrity: crate::rpc_api::Algorithm {
                    id: 1024,
                    name: String::new(),
                    key: Vec::new(),
                },
                lifetime: Some(crate::rpc_api::Lifetime {
                    time: crate::rpc_api::LifetimeLimit {
                        life: 0,
                        rekey: 0,
                        jitter: 0,
                    },
                    bytes: crate::rpc_api::LifetimeLimit {
                        life: 0,
                        rekey: 0,
                        jitter: 0,
                    },
                    packets: crate::rpc_api::LifetimeLimit {
                        life: 0,
                        rekey: 0,
                        jitter: 0,
                    },
                }),
                replay_window: 128,
                ipcomp: 0,
                cpi: 0,
                cpu: u32::MAX,
                hw_offload: 0,
                security_label: None,
                tfc: 0,
                udp_encapsulation: true,
                output_mark: Mark::default(),
                esn: true,
                copy_df: true,
                copy_ecn: true,
                copy_dscp: 0,
                iptfs_dont_fragment: false,
                forward_icmp: false,
                initiator: true,
                inbound: false,
                update: false,
            },
        )
    }
    #[test]
    fn audits_retire_loss_and_drift_without_reinstalling() {
        let (id, data) = fixture();
        let mut sas = Sas::new(MemoryKernel::default());
        sas.install(&id, &data).unwrap();
        sas.kernel.objects.get_mut(&id.key()).unwrap().3 = SaUsage {
            bytes: 100,
            packets: 10,
            last_use: 5,
        };
        assert!(sas.reconcile().unwrap().expired.is_empty());
        assert_eq!(sas.query(&id).unwrap().packets, 10);
        sas.kernel.objects.get_mut(&id.key()).unwrap().0 = Some(43);
        assert_eq!(sas.reconcile().unwrap().expired, vec![id.key()]);
        assert!(sas.kernel.objects.is_empty());
        assert!(sas.reconcile().unwrap().expired.is_empty());
        assert_eq!(sas.kernel.creates, 1);
        sas.install(&id, &data).unwrap();
        sas.kernel.objects.clear();
        assert_eq!(sas.reconcile().unwrap().expired, vec![id.key()]);
        assert_eq!(sas.kernel.creates, 2);
        sas.remove(&id).unwrap();
    }
    #[test]
    fn failed_inventory_does_not_expire_and_failed_cleanup_does_not_lose_events() {
        let (id, data) = fixture();
        let mut sas = Sas::new(MemoryKernel::default());
        sas.install(&id, &data).unwrap();
        sas.kernel.fail_list = true;
        assert!(sas.reconcile().is_err());
        assert!(sas.contains(&id));
        sas.kernel.fail_list = false;
        sas.kernel.objects.get_mut(&id.key()).unwrap().2 += 1;
        sas.kernel.fail_delete = true;
        let changes = sas.reconcile().unwrap();
        assert_eq!(changes.expired, vec![id.key()]);
        assert!(changes.cleanup_error.is_some());
        assert!(!sas.contains(&id));
        sas.kernel.fail_delete = false;
        assert!(sas.reconcile().unwrap().expired.is_empty());
        assert!(sas.kernel.objects.is_empty());
    }
    #[test]
    fn reservations_are_not_established_and_expiry_is_not_resurrected() {
        let (mut id, mut data) = fixture();
        let mut sas = Sas::new(MemoryKernel::default());
        id.spi = sas
            .allocate(id.src, id.dst, 50, 0xc0000000, 0xcfffffff)
            .unwrap();
        assert!(sas.reconcile().unwrap().expired.is_empty());
        assert_eq!(sas.kernel.objects.len(), 1);
        data.update = true;
        sas.kernel.objects.clear(); // Expired reservation is safe to complete.
        sas.install(&id, &data).unwrap();
        assert_eq!(
            sas.install(&id, &data).unwrap_err().raw_os_error(),
            Some(libc::EEXIST)
        );
        assert!(sas.expire(&id, true));
        assert!(!sas.expire(&id, true));
        assert_eq!(
            sas.install(&id, &data).unwrap_err().raw_os_error(),
            Some(libc::ENOENT)
        );
        assert!(sas.reconcile().unwrap().expired.is_empty());
        assert!(sas.kernel.objects.is_empty());
    }
    #[test]
    fn removing_one_sa_keeps_overlapping_rekey_and_prunes_unwanted_objects() {
        let (old, data) = fixture();
        let mut new = old.clone();
        new.spi += 1;
        let mut sas = Sas::new(MemoryKernel::default());
        sas.install(&old, &data).unwrap();
        sas.install(&new, &data).unwrap();
        sas.remove(&old).unwrap();
        sas.kernel.objects.insert(
            old.key(),
            (Some(42), SaState::Installed, 10, SaUsage::default()),
        );
        assert!(sas.reconcile().unwrap().expired.is_empty());
        assert!(!sas.kernel.objects.contains_key(&old.key()));
        assert!(sas.contains(&new));
        sas.clear().unwrap();
        assert!(sas.is_empty() && sas.kernel.objects.is_empty());
    }
}
