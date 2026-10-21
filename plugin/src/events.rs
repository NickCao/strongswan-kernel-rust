// SPDX-License-Identifier: GPL-2.0-or-later
//! Drain daemon events as a fairly requeued job on charon's existing workers.
use crate::{ffi, host, log};
use foreign_types::ForeignType;
use kernel_rust_protocol::{
    self as api,
    client::{CancellationToken, Client},
};
use std::{
    ptr,
    sync::{Arc, Mutex, Weak},
};

struct State {
    client: Weak<Client>,
    stop: CancellationToken,
    active: Mutex<()>,
}
pub struct EventJob {
    state: Arc<State>,
}
impl EventJob {
    /// # Safety
    /// The host processor/kernel must outlive this registration. Charon cancels
    /// and destroys queued jobs before unloading plugin libraries.
    pub unsafe fn register(client: &Arc<Client>) -> Self {
        let state = Arc::new(State {
            client: Arc::downgrade(client),
            stop: CancellationToken::new(),
            active: Mutex::new(()),
        });
        // SAFETY: the job owns this Arc until its cleanup callback. The handle
        // retains another Arc to cancel and join active callbacks on drop.
        let data = Arc::into_raw(state.clone()).cast_mut().cast();
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
        Self { state }
    }
}
impl Drop for EventJob {
    fn drop(&mut self) {
        self.state.stop.cancel();
        // Cancellation wakes a pending event RPC. Wait for event dispatch to
        // finish, but a queued/stopped job need not run to release the client.
        let _active = self.state.active.lock().unwrap();
    }
}
unsafe extern "C" fn receive_events(data: *mut libc::c_void) -> ffi::job_requeue_t {
    // SAFETY: callback_job owns an Arc<State> until cleanup(). Its callbacks
    // borrow it; only cleanup reconstructs and releases that Arc.
    let state = unsafe { &*data.cast::<State>() };
    let _active = state.active.lock().unwrap();
    if !state.stop.is_cancelled() {
        if let Some(client) = state.client.upgrade() {
            match client.next_events(&state.stop) {
                Ok(Some(batch)) => {
                    for event in batch {
                        if state.stop.is_cancelled() {
                            break;
                        }
                        dispatch(event);
                    }
                    return requeue(ffi::job_requeue_type_t_JOB_REQUEUE_TYPE_FAIR);
                }
                Ok(None) => (),
                Err(error) => log(&format!("receiving events: {error}")),
            }
        }
    }
    requeue(ffi::job_requeue_type_t_JOB_REQUEUE_TYPE_NONE)
}
unsafe extern "C" fn cancel(data: *mut libc::c_void) -> bool {
    // SAFETY: the processor holds the job alive throughout cancellation.
    unsafe { &*data.cast::<State>() }.stop.cancel();
    true // Return normally; never pthread-cancel through Rust stack frames.
}
unsafe extern "C" fn cleanup(data: *mut libc::c_void) {
    // SAFETY: paired with the single Arc::into_raw() in register().
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
