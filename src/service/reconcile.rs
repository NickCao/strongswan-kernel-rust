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
    while session.connected.load(Ordering::Acquire) && !session.closed.load(Ordering::Acquire) {
        match tokio::time::timeout_at(next_audit, wakeup.recv()).await {
            Ok(Some(())) => {
                // Bound the delay even during continuous policy/link updates.
                next_audit = next_audit.min(Instant::now() + REPAIR_DELAY);
            }
            Err(_) => (),
            Ok(None) => break,
        }
        if Instant::now() < next_audit {
            continue;
        }
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
        if let Err(error) = backend.reconcile_interfaces().await {
            eprintln!("kernel-daemon: interface reconciliation: {error}");
            if session.fail_on_transport_error(&error) {
                return;
            }
        }
        if let Err(error) = backend.policies.reconcile().await {
            eprintln!("kernel-daemon: policy reconciliation: {error}");
            if session.fail_on_transport_error(&error) {
                return;
            }
        }
        next_audit = Instant::now() + AUDIT_INTERVAL;
    }
}
