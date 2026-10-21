// SPDX-License-Identifier: GPL-2.0-or-later
//! Wake a charon pool job from socket readiness or buffered RPC notifications.
use crate::{ffi, host, log};
use foreign_types::ForeignType;
use kernel_rust_protocol::{
    self as api,
    client::{CancellationToken, Client},
    transport::EventSignal,
};
use std::{
    os::fd::AsRawFd,
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, Weak,
    },
};

struct State {
    client: Weak<Client>,
    stop: CancellationToken,
    // Serializes event dispatch and remembers whether another batch is due.
    active: Mutex<bool>,
    registration: Mutex<()>,
    queued: AtomicBool,
    armed: AtomicBool,
    signal: Arc<EventSignal>,
    fd: i32,
}
pub struct EventJob {
    state: Arc<State>,
}
impl EventJob {
    /// # Safety
    /// The host processor/watcher/kernel must outlive this registration. Charon
    /// cancels and destroys queued jobs before unloading plugin libraries.
    pub unsafe fn register(client: &Arc<Client>) -> Self {
        let state = Arc::new(State {
            client: Arc::downgrade(client),
            stop: CancellationToken::new(),
            active: Mutex::new(false),
            registration: Mutex::new(()),
            queued: AtomicBool::new(false),
            armed: AtomicBool::new(false),
            signal: client.event_signal().clone(),
            fd: client.socket().as_raw_fd(),
        });
        let weak = Arc::downgrade(&state);
        state.signal.set_waker(Some(Arc::new(move || {
            if let Some(state) = weak.upgrade() {
                state.schedule();
            }
        })));
        state.arm();
        Self { state }
    }
}
impl State {
    fn schedule(self: &Arc<Self>) {
        let _registration = self.registration.lock().unwrap();
        if self.stop.is_cancelled() || self.queued.swap(true, Ordering::AcqRel) {
            return;
        }
        // SAFETY: the job owns this Arc until its cleanup callback. The handle
        // retains another Arc to cancel and join active callbacks on drop.
        let data = Arc::into_raw(self.clone()).cast_mut().cast();
        unsafe {
            let job = ffi::callback_job_create_with_prio(
                Some(receive_events),
                data,
                Some(cleanup),
                Some(cancel),
                ffi::job_priority_t_JOB_PRIO_LOW,
            );
            let processor = (*ffi::lib).processor;
            (*processor).queue_job.unwrap()(processor, job.cast());
        }
    }
    fn arm(&self) {
        let _registration = self.registration.lock().unwrap();
        if self.stop.is_cancelled() || self.armed.swap(true, Ordering::AcqRel) {
            return;
        }
        // SAFETY: EventJob retains the State and the client's FD until remove()
        // joins callbacks. Queued jobs cannot rearm after Drop sets stop.
        unsafe {
            let watcher = (*ffi::lib).watcher;
            (*watcher).add.unwrap()(
                watcher,
                self.fd,
                ffi::watcher_event_t_WATCHER_READ,
                Some(socket_ready),
                ptr::from_ref(self).cast_mut().cast(),
            );
        }
    }
}
impl Drop for EventJob {
    fn drop(&mut self) {
        {
            let _registration = self.state.registration.lock().unwrap();
            self.state.stop.cancel();
        }
        self.state.signal.set_waker(None);
        // SAFETY: the FD and State remain live through removal. This waits for
        // the short watcher callback; RPCs run only in cancellable pool jobs.
        unsafe {
            let watcher = (*ffi::lib).watcher;
            (*watcher).remove.unwrap()(watcher, self.state.fd);
        }
        // Cancellation wakes a pending event RPC. Wait for event dispatch to
        // finish, but a queued/stopped job need not run to release the client.
        let _active = self.state.active.lock().unwrap();
    }
}
unsafe extern "C" fn socket_ready(
    data: *mut libc::c_void,
    _fd: i32,
    _event: ffi::watcher_event_t,
) -> bool {
    // SAFETY: EventJob retains State until watcher.remove() joins this callback.
    let state = unsafe { &*data.cast::<State>() };
    state.armed.store(false, Ordering::Release);
    state.signal.wake();
    // One-shot watching avoids repeatedly dispatching the same unread socket
    // while the low-priority event job waits for a worker. The job rearms it.
    false
}
unsafe extern "C" fn receive_events(data: *mut libc::c_void) -> ffi::job_requeue_t {
    // SAFETY: callback_job owns an Arc<State> until cleanup(). Its callbacks
    // borrow it; only cleanup reconstructs and releases that Arc.
    let state = unsafe { &*data.cast::<State>() };
    let mut draining = state.active.lock().unwrap();
    if !state.stop.is_cancelled() {
        if let Some(client) = state.client.upgrade() {
            if *draining || client.events_ready().unwrap_or(true) {
                match client.next_events(&state.stop) {
                    Ok(Some(batch)) => {
                        *draining = !batch.is_empty();
                        for event in batch {
                            if state.stop.is_cancelled() {
                                break;
                            }
                            dispatch(event);
                        }
                    }
                    Ok(None) => state.stop.cancel(),
                    Err(error) => {
                        log(&format!("receiving events: {error}"));
                        state.stop.cancel();
                    }
                }
            }
            if !state.stop.is_cancelled() {
                if *draining || state.signal.is_pending() {
                    return requeue(ffi::job_requeue_type_t_JOB_REQUEUE_TYPE_FAIR);
                }
                state.queued.store(false, Ordering::Release);
                // A notification racing the empty reply either queues its own
                // job after the store above or is retained by this one.
                if state.signal.is_pending() && !state.queued.swap(true, Ordering::AcqRel) {
                    return requeue(ffi::job_requeue_type_t_JOB_REQUEUE_TYPE_FAIR);
                }
                state.arm();
                return requeue(ffi::job_requeue_type_t_JOB_REQUEUE_TYPE_NONE);
            }
        }
    }
    state.queued.store(false, Ordering::Release);
    requeue(ffi::job_requeue_type_t_JOB_REQUEUE_TYPE_NONE)
}
unsafe extern "C" fn cancel(data: *mut libc::c_void) -> bool {
    // SAFETY: the processor holds the job alive throughout cancellation.
    unsafe { &*data.cast::<State>() }.stop.cancel();
    true // Return normally; never pthread-cancel through Rust stack frames.
}
unsafe extern "C" fn cleanup(data: *mut libc::c_void) {
    // SAFETY: paired with the Arc::into_raw() for this queued job in schedule().
    drop(unsafe { Arc::from_raw(data.cast::<State>()) });
}
fn requeue(kind: ffi::job_requeue_type_t) -> ffi::job_requeue_t {
    ffi::job_requeue_t {
        type_: kind,
        ..Default::default()
    }
}

fn dispatch(event: api::Event) {
    // The job runs on charon's workers while the kernel interface is alive.
    let kernel = unsafe { (*ffi::charon).kernel };
    match event.kind {
        api::EventKind::Expire => {
            if let Some(e) = event.expiry {
                if let Ok(dst) = host::Host::parse(&e.destination) {
                    // SAFETY: the owned destination stays alive; the host clones
                    // its borrowed event arguments if it needs to retain them.
                    unsafe {
                        (*kernel).expire.unwrap()(
                            kernel,
                            e.protocol,
                            e.spi.to_be(),
                            dst.as_ptr(),
                            e.hard,
                        );
                    }
                }
            }
        }
        api::EventKind::Mapping => {
            if let Some(e) = event.mapping {
                if let (Ok(dst), Ok(remote)) = (
                    host::Host::parse(&e.destination),
                    host::Host::parse(&e.remote),
                ) {
                    // SAFETY: both privately owned C objects outlive this call.
                    unsafe {
                        (*kernel).mapping.unwrap()(
                            kernel,
                            libc::IPPROTO_ESP as u8,
                            e.spi.to_be(),
                            dst.as_ptr(),
                            remote.as_ptr(),
                        );
                    }
                }
            }
        }
        api::EventKind::Acquire => {
            if let Some(e) = event.acquire {
                if let (Ok(src), Ok(dst)) =
                    (host::Selector::parse(&e.src), host::Selector::parse(&e.dst))
                {
                    let mut data = ffi::kernel_acquire_data_t {
                        src: src.as_ptr(),
                        dst: dst.as_ptr(),
                        label: ptr::null_mut(),
                        cpu: ffi::CPU_ID_MAX,
                        seq: e.sequence,
                    };
                    // SAFETY: selectors and the stack record outlive the call.
                    unsafe {
                        (*kernel).acquire.unwrap()(kernel, e.reqid, &mut data);
                    }
                }
            }
        }
        api::EventKind::Roam => {
            if let Some(address) = event.address_changed {
                // SAFETY: the kernel interface remains live for this callback.
                unsafe {
                    (*kernel).roam.unwrap()(kernel, address);
                }
            }
        }
    }
}
