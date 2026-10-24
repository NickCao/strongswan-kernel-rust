// SPDX-License-Identifier: GPL-2.0-or-later
//! Coalesced repairs and periodic audits, serialized with session mutations.
use super::Session;
use crate::rpc_api::{Event, Expiry};
use std::{
    sync::{atomic::Ordering, Arc},
    time::Duration,
};

use tokio::{sync::mpsc::Receiver, time::Instant};

const REPAIR_DELAY: Duration = Duration::from_millis(100);
const AUDIT_INTERVAL: Duration = Duration::from_secs(5);

pub(super) async fn run(session: Arc<Session>, mut wakeup: Receiver<()>) {
    let mut next_audit = Instant::now() + AUDIT_INTERVAL;
    let mut next_repair = next_audit;
    while session.connected.load(Ordering::Acquire) && !session.closed.load(Ordering::Acquire) {
        match tokio::time::timeout_at(next_repair.min(next_audit), wakeup.recv()).await {
            Ok(Some(())) => {
                // Bound the delay even during continuous SA/policy updates.
                next_repair = next_repair.min(Instant::now() + REPAIR_DELAY);
            }
            Err(_) => (),
            Ok(None) => break,
        }
        if Instant::now() < next_repair.min(next_audit) {
            continue;
        }
        // Interface inventory stays on the periodic deadline even when XFRM
        // notifications request earlier SA/policy repairs.
        // Keep this lock through inventory, retirement and policy/link repairs.
        // Install/delete/rekey requests use this same lock.
        let mut backend = session.backend.lock().await;
        if !session.connected.load(Ordering::Acquire) || session.closed.load(Ordering::Acquire) {
            break;
        }
        match backend.reconcile_sas().await {
            Ok(changes) => {
                if let Some(error) = changes.cleanup_error {
                    eprintln!("kernel-daemon: SA cleanup: {error}");
                    if session.fail_on_transport_error(&error) {
                        return;
                    }
                }
                // One bounded queue entry per inventory, so a flush of
                // hundreds of SAs cannot overflow the queue with expirations.
                let events: Vec<_> = changes
                    .expired
                    .into_iter()
                    .map(|id| {
                        Event::Expire(Expiry {
                            protocol: id.proto,
                            spi: id.spi,
                            destination: id.dst,
                            hard: true,
                        })
                    })
                    .collect();
                if !events.is_empty() {
                    session.emit_events(events);
                }
            }
            Err(error) => {
                eprintln!("kernel-daemon: SA inventory: {error}");
                if session.fail_on_transport_error(&error) {
                    return;
                }
            }
        }
        if Instant::now() >= next_audit {
            if let Err(error) = backend.reconcile_interfaces().await {
                eprintln!("kernel-daemon: interface reconciliation: {error}");
                if session.fail_on_transport_error(&error) {
                    return;
                }
            }
            next_audit = Instant::now() + AUDIT_INTERVAL;
        }
        if let Err(error) = backend.policies.reconcile().await {
            eprintln!("kernel-daemon: policy reconciliation: {error}");
            if session.fail_on_transport_error(&error) {
                return;
            }
        }
        next_repair = next_audit;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        linux::network::Network,
        rpc_api::{context, Kernel, SessionConfig},
        service::{Server, Service},
    };
    use std::{os::unix::net::UnixStream, process::Command};

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires root and iproute2; creates a network namespace"]
    async fn notifications_neither_advance_nor_postpone_interface_audits() {
        let _namespace = crate::test_netns::Netns::new();
        let server = Arc::new(Server::new("tst".into(), None, 1400, 17227).unwrap());
        let (socket, _peer) = UnixStream::pair().unwrap();
        let service = Service::new(server.clone(), socket);
        service
            .clone()
            .open_session(context::current(), SessionConfig::default())
            .await
            .unwrap();
        let session = service.control.lock().unwrap().clone().unwrap();
        let mut net = Network::new().await.unwrap();
        // An unwanted owned link makes full inventories observable without
        // adding counters or another copy of interface state to the service.
        let output = Command::new("ip")
            .args([
                "link",
                "add",
                "audit-orphan",
                "group",
                "17227",
                "type",
                "dummy",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        tokio::time::sleep(REPAIR_DELAY * 3).await;
        assert!(
            net.link_by_name("audit-orphan").await.unwrap().is_some(),
            "a link notification must not trigger interface inventory"
        );

        session.repair_wakeup.try_send(()).unwrap();
        tokio::time::sleep(REPAIR_DELAY * 3).await;
        assert!(
            net.link_by_name("audit-orphan").await.unwrap().is_some(),
            "SA/policy repair wakeups must not trigger interface inventory"
        );

        // Keep requesting SA/policy repairs. The periodic interface audit must
        // still arrive on its own deadline rather than waiting for silence.
        tokio::time::timeout(AUDIT_INTERVAL + Duration::from_secs(2), async {
            loop {
                let _ = session.repair_wakeup.try_send(());
                if net.link_by_name("audit-orphan").await.unwrap().is_none() {
                    break;
                }
                tokio::time::sleep(REPAIR_DELAY / 2).await;
            }
        })
        .await
        .expect("continuous repair wakeups postponed the interface audit");

        service.close_session(context::current()).await.unwrap();
        server.shutdown().await.unwrap();
    }
}
