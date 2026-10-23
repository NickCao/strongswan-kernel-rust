// SPDX-License-Identifier: GPL-2.0-or-later
//! Kernel notifications, event buffering and coalesced client wakeups.
use super::{Service, Session};
use crate::{
    backend::Backend,
    linux::{netlink::Notifications, xfrm},
    rpc_api::{Error, Event, Result},
};
use neli::consts::rtnl::Rtm;
use std::{
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

const ROAM_DELAY: Duration = Duration::from_millis(100);
const ROUTE_CHANGED: u8 = 1;
const ADDRESS_CHANGED: u8 = 2;

pub(super) struct Watch {
    session: Arc<Session>,
    receiver: tokio::sync::mpsc::Receiver<Option<Vec<Event>>>,
    next_roam: Instant,
    notified: bool,
}
impl Watch {
    pub(super) fn new(
        session: Arc<Session>,
        receiver: tokio::sync::mpsc::Receiver<Option<Vec<Event>>>,
    ) -> Self {
        Self {
            session,
            receiver,
            next_roam: Instant::now() + ROAM_DELAY,
            notified: false,
        }
    }
}

impl Service {
    /// One coalesced transport wakeup per change. XFRM batches wake immediately;
    /// a pending roam waits until its existing coalescing deadline, and a new
    /// XFRM batch can interrupt that wait. No backend lock is held while waiting.
    pub async fn next_notification(&self) -> Option<()> {
        loop {
            let due = {
                let mut guard = self.watch.lock().await;
                if let Some(watch) = guard.as_mut() {
                    let session = &watch.session;
                    if session.closed.load(Ordering::Acquire)
                        || !session.connected.load(Ordering::Acquire)
                    {
                        return None;
                    }
                    let roam = session.roam.load(Ordering::Relaxed) != 0;
                    if !watch.notified
                        && (!watch.receiver.is_empty() || roam && Instant::now() >= watch.next_roam)
                    {
                        watch.notified = true;
                        return Some(());
                    }
                    if !watch.notified && roam {
                        Some(watch.next_roam)
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            if let Some(due) = due {
                tokio::select! {
                    _ = self.event_wakeup.notified() => (),
                    _ = tokio::time::sleep_until(due.into()) => (),
                }
            } else {
                self.event_wakeup.notified().await;
            }
        }
    }
    pub(super) async fn fetch_events(&self) -> Result<Vec<Event>> {
        let mut guard = self.watch.lock().await;
        let watch = guard.as_mut().ok_or(Error::InvalidSession)?;
        let session = &watch.session;
        if !session.connected.load(Ordering::Acquire) || session.closed.load(Ordering::Acquire) {
            return Err(Error::InvalidSession);
        }
        watch.notified = false;
        let mut batch = match watch.receiver.try_recv() {
            Ok(Some(batch)) => batch,
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => Vec::new(),
            _ => return Err(Error::InvalidSession),
        };
        if Instant::now() >= watch.next_roam {
            watch.next_roam = Instant::now() + ROAM_DELAY;
            let changes = session.roam.swap(0, Ordering::Relaxed);
            if changes != 0 {
                batch.push(Event::Roam {
                    address_changed: changes & ADDRESS_CHANGED != 0,
                });
            }
        }
        self.event_wakeup.notify_one();
        Ok(batch)
    }
}

pub(super) async fn run(session: Arc<Session>, xfrm: bool, mut notifications: Notifications) {
    while let Some(notification) = notifications.next().await {
        if session.closed.load(Ordering::Acquire) {
            return;
        }
        let r = match notification {
            Ok(reply) => reply,
            Err(error) => {
                eprintln!(
                    "kernel-daemon: {} notification: {error}",
                    if xfrm { "XFRM" } else { "network" }
                );
                session.fail();
                return;
            }
        };
        if !xfrm {
            // A routing daemon can send thousands of notifications per second.
            // Keep one pending roam update, retaining address/link changes,
            // instead of queueing a separate IKE-wide job for every route.
            let kind = Rtm::from(r.kind);
            if matches!(kind, Rtm::Newlink | Rtm::Dellink) {
                let _ = session.repair_wakeup.try_send(());
            }
            let change = match kind {
                Rtm::Newlink | Rtm::Dellink | Rtm::Newaddr | Rtm::Deladdr => {
                    session.network_changed.store(true, Ordering::Release);
                    ADDRESS_CHANGED
                }
                _ => ROUTE_CHANGED,
            };
            if session.roam.fetch_or(change, Ordering::Relaxed) == 0 {
                session.event_wakeup.notify_one();
            }
            continue;
        }
        if matches!(
            r.kind,
            netlink_packet_xfrm::XFRM_MSG_NEWSA
                | netlink_packet_xfrm::XFRM_MSG_UPDSA
                | netlink_packet_xfrm::XFRM_MSG_DELSA
                | netlink_packet_xfrm::XFRM_MSG_FLUSHSA
                | netlink_packet_xfrm::XFRM_MSG_NEWPOLICY
                | netlink_packet_xfrm::XFRM_MSG_UPDPOLICY
                | netlink_packet_xfrm::XFRM_MSG_DELPOLICY
                | netlink_packet_xfrm::XFRM_MSG_FLUSHPOLICY
                | netlink_packet_xfrm::XFRM_MSG_POLEXPIRE
        ) {
            let _ = session.repair_wakeup.try_send(());
            continue;
        }
        let result = {
            let mut backend = session.backend.lock().await;
            if session.closed.load(Ordering::Acquire) {
                return;
            }
            let Backend { sas, policies, .. } = &mut *backend;
            let result = xfrm::event(&r, sas, policies);
            if let Err(e) = backend.cleanup_interfaces().await {
                eprintln!("kernel-daemon: interface cleanup: {e}");
            }
            result
        };
        match result {
            Ok(Some(event)) if session.connected.load(Ordering::Acquire) => {
                session.emit_events(vec![event]);
            }
            Err(e) => eprintln!("kernel-daemon: kernel event: {e}"),
            _ => (),
        }
    }
    if !session.closed.load(Ordering::Acquire) {
        session.fail();
    }
}
#[cfg(test)]
mod tests {
    use super::super::Server;
    use super::*;
    use crate::rpc_api::{context, Endpoint, Expiry, Kernel, SessionConfig};
    use std::os::unix::net::UnixStream;

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires root; creates a network namespace"]
    async fn urgent_push_preserves_the_pending_roam_deadline() {
        let _namespace = crate::test_netns::Netns::new();
        let server = Arc::new(Server::new("tst".into(), None, 1400, 17227).unwrap());
        let (socket, _peer) = UnixStream::pair().unwrap();
        let service = Service::new(server.clone(), socket);
        service
            .clone()
            .open_session(
                context::current(),
                SessionConfig {
                    interfaces_use: String::new(),
                    interfaces_ignore: String::new(),
                    ..SessionConfig::default()
                },
            )
            .await
            .unwrap();
        let session = {
            let mut guard = service.watch.lock().await;
            let watch = guard.as_mut().unwrap();
            watch.next_roam = Instant::now() + Duration::from_millis(150);
            watch.session.roam.store(ROUTE_CHANGED, Ordering::Relaxed);
            watch.session.clone()
        };
        session.event_wakeup.notify_one();
        let pending = tokio::spawn({
            let service = service.clone();
            async move { service.next_notification().await }
        });
        tokio::time::sleep(Duration::from_millis(5)).await;
        session.emit_events(vec![Event::Expire(Expiry {
            protocol: 50,
            spi: 7,
            destination: Endpoint {
                address: "192.0.2.1".parse().unwrap(),
                port: 0,
                flow_info: 0,
                scope_id: 0,
            },
            hard: true,
        })]);
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(100), pending)
                .await
                .unwrap()
                .unwrap(),
            Some(())
        );
        let batch = service
            .clone()
            .next_events(context::current())
            .await
            .unwrap();
        assert_eq!(batch.len(), 1);
        assert!(matches!(batch[0], Event::Expire(_)));
        // No further route change or XFRM event arrives. The original pending
        // roam must still produce its own push at the coalescing deadline.
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), service.next_notification())
                .await
                .unwrap(),
            Some(())
        );
        let batch = service
            .clone()
            .next_events(context::current())
            .await
            .unwrap();
        assert_eq!(batch.len(), 1);
        assert!(matches!(
            batch[0],
            Event::Roam {
                address_changed: false
            }
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), service.next_notification())
                .await
                .is_err(),
            "no periodic pushes when idle"
        );
        service.close_session(context::current()).await.unwrap();
        server.shutdown().await.unwrap();
    }
}
