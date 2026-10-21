// SPDX-License-Identifier: GPL-2.0-or-later
//! Real daemon/kernel contracts. Each ignored case owns a new network namespace;
//! run with `cargo test --test daemon -- --ignored` as root. Cases may run in parallel.
#![forbid(unsafe_code)]
mod common;
use common::*;
use kernel_rust_protocol::{context::current as ctx, *};
use rstest::{fixture, rstest};

#[path = "daemon/interfaces.rs"]
mod interfaces;
#[path = "daemon/lifecycle.rs"]
mod lifecycle;
#[path = "daemon/network.rs"]
mod network;
#[path = "daemon/policies.rs"]
mod policies;
#[path = "daemon/sas.rs"]
mod sas;

struct Fixture {
    daemon: Daemon,
    _namespace: common::netns::Netns,
}
impl std::ops::Deref for Fixture {
    type Target = Daemon;
    fn deref(&self) -> &Daemon {
        &self.daemon
    }
}
impl std::ops::DerefMut for Fixture {
    fn deref_mut(&mut self) -> &mut Daemon {
        &mut self.daemon
    }
}
#[fixture]
fn namespace() -> common::netns::Netns {
    let namespace = common::netns::Netns::new();
    ip(&["link", "set", "lo", "up"]);
    ip(&["link", "add", "underlay", "type", "dummy"]);
    ip(&["link", "set", "underlay", "up"]);
    ip(&["addr", "add", "192.0.2.1/24", "dev", "underlay"]);
    ip(&[
        "-6",
        "addr",
        "add",
        "2001:db8:1::1/64",
        "dev",
        "underlay",
        "nodad",
    ]);
    namespace
}
#[fixture]
fn daemon(namespace: common::netns::Netns) -> Fixture {
    Fixture {
        daemon: Daemon::start(&[]),
        _namespace: namespace,
    }
}
