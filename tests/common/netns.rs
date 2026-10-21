// SPDX-License-Identifier: GPL-2.0-or-later
use nix::sched::{setns, unshare, CloneFlags};
use std::{fs::File, marker::PhantomData, rc::Rc};

/// A namespace belongs to the calling test thread. Drop restores that thread
/// after its daemon, sockets and runtime have been dropped.
pub struct Netns {
    original: File,
    _thread: PhantomData<Rc<()>>,
}
impl Netns {
    pub fn new() -> Self {
        let original = File::open("/proc/thread-self/ns/net").unwrap();
        unshare(CloneFlags::CLONE_NEWNET)
            .expect("kernel tests need permission to create a network namespace (run as root)");
        Self {
            original,
            _thread: PhantomData,
        }
    }
}
impl Drop for Netns {
    fn drop(&mut self) {
        setns(&self.original, CloneFlags::CLONE_NEWNET).expect("restore test network namespace");
    }
}
