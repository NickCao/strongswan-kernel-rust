// SPDX-License-Identifier: GPL-2.0-or-later
//! The watcher clears eventfd wakeups; cancellable pool jobs fetch events.
use crate::{ffi, host, log_error};
use foreign_types::ForeignType;
use kernel_rust_protocol::{
    self as api,
    client::{CancellationToken, Client},
};
use std::{
    os::fd::{AsFd, AsRawFd},
    ptr,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc, Mutex, Weak,
    },
};

const QUEUED: u8 = 1;
const READY: u8 = 2;
struct State {
    this: Weak<State>,
    client: Weak<Client>,
    stop: CancellationToken,
    active: Mutex<()>,
    // One job owns QUEUED. READY retains wakeups arriving during its RPC.
    pending: AtomicU8,
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
        let state = Arc::new_cyclic(|this| State {
            this: this.clone(),
            client: Arc::downgrade(client),
            stop: CancellationToken::new(),
            active: Mutex::new(()),
            pending: AtomicU8::new(0),
            fd: client.notification().as_fd().as_raw_fd(),
        });
        // SAFETY: the State and the client's FD remain live until
        // Drop removes the watcher and joins its callbacks.
        unsafe {
            let watcher = (*ffi::lib).watcher;
            (*watcher).add.unwrap()(
                watcher,
                state.fd,
                ffi::watcher_event_t_WATCHER_READ,
                Some(notification_ready),
                ptr::from_ref(&*state).cast_mut().cast(),
            );
        }
        Self { state }
    }
}
impl State {
    fn schedule(self: &Arc<Self>) {
        if self.stop.is_cancelled()
            || self.pending.fetch_or(QUEUED | READY, Ordering::AcqRel) & QUEUED != 0
        {
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
}
impl Drop for EventJob {
    fn drop(&mut self) {
        self.state.stop.cancel();
        // SAFETY: the FD and State remain live through removal, which joins
        // the short callback. Queued/stopped jobs retain only a weak client.
        unsafe {
            let watcher = (*ffi::lib).watcher;
            (*watcher).remove.unwrap()(watcher, self.state.fd);
        }
        let _active = self.state.active.lock().unwrap();
    }
}
unsafe extern "C" fn notification_ready(
    data: *mut libc::c_void,
    _fd: i32,
    _event: ffi::watcher_event_t,
) -> bool {
    // SAFETY: EventJob retains State until remove() joins this callback.
    let state = unsafe { &*data.cast::<State>() };
    if state.stop.is_cancelled() {
        return false;
    }
    let Some(client) = state.client.upgrade() else {
        return false;
    };
    match client.notification().drain() {
        Ok(true) => {
            if let Some(state) = state.this.upgrade() {
                state.schedule();
            }
        }
        Ok(false) => (),
        Err(error) => {
            log_error("reading eventfd", &error);
            state.stop.cancel();
            return false;
        }
    }
    true
}
unsafe extern "C" fn receive_events(data: *mut libc::c_void) -> ffi::job_requeue_t {
    // SAFETY: callback_job owns an Arc<State> until cleanup().
    let state = unsafe { &*data.cast::<State>() };
    let _active = state.active.lock().unwrap();
    state.pending.fetch_and(!READY, Ordering::AcqRel);
    if !state.stop.is_cancelled() {
        if let Some(client) = state.client.upgrade() {
            match client.next_events(&state.stop) {
                Ok(Some(batch)) => {
                    let more = !batch.is_empty();
                    for event in batch {
                        if state.stop.is_cancelled() {
                            break;
                        }
                        dispatch(event);
                    }
                    if !state.stop.is_cancelled() {
                        // A racing wakeup either keeps this job alive or queues
                        // another one after this atomic release of QUEUED.
                        if more
                            || state
                                .pending
                                .compare_exchange(QUEUED, 0, Ordering::AcqRel, Ordering::Acquire)
                                .is_err()
                        {
                            return requeue(ffi::job_requeue_type_t_JOB_REQUEUE_TYPE_FAIR);
                        }
                        return requeue(ffi::job_requeue_type_t_JOB_REQUEUE_TYPE_NONE);
                    }
                }
                Ok(None) => state.stop.cancel(),
                Err(error) => {
                    log_error("next_events", &error);
                    state.stop.cancel();
                }
            }
        }
    }
    state.pending.store(0, Ordering::Release);
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
    match event {
        api::Event::Expire(e) => {
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
        api::Event::Mapping(e) => {
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
        api::Event::Acquire(e) => {
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
        api::Event::Roam { address_changed } => {
            // SAFETY: the kernel interface remains live for this callback.
            unsafe {
                (*kernel).roam.unwrap()(kernel, address_changed);
            }
        }
    }
}
