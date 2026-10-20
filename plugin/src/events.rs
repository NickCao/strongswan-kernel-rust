// SPDX-License-Identifier: GPL-2.0-or-later
//! The C watcher boundary; the RPC client and event stream are safe Rust.
use crate::{ffi, host};
use foreign_types::ForeignType;
use kernel_rust_protocol::{
    self as api,
    client::{Client, Events},
};
use std::{
    io,
    os::fd::AsRawFd,
    ptr,
    sync::{Arc, Mutex},
};

struct State {
    client: Arc<Client>,
    events: Mutex<Events>,
}
pub struct Watcher {
    _state: Arc<State>,
    watcher: *mut ffi::watcher_t,
    fd: i32,
}
impl Watcher {
    /// # Safety
    /// The strongSwan library and watcher must outlive this registration.
    pub unsafe fn register(client: Arc<Client>, events: Events) -> Self {
        let fd = std::os::fd::AsFd::as_fd(&events).as_raw_fd();
        let state = Arc::new(State {
            client,
            events: Mutex::new(events),
        });
        let watcher = unsafe { (*ffi::lib).watcher };
        // SAFETY: Arc keeps the shared callback data stable until remove()
        // completes; dropping the registration never borrows State exclusively.
        unsafe {
            (*watcher).add.unwrap()(
                watcher,
                fd,
                ffi::watcher_event_t_WATCHER_READ,
                Some(receive_events),
                ptr::from_ref(&*state).cast_mut().cast(),
            );
        }
        Self {
            _state: state,
            watcher,
            fd,
        }
    }
}
impl Drop for Watcher {
    fn drop(&mut self) {
        // SAFETY: remove waits for all in-flight callbacks before state and its
        // owned event socket are freed. No exclusive reference to State is made.
        unsafe {
            (*self.watcher).remove.unwrap()(self.watcher, self.fd);
        }
    }
}
impl State {
    fn receive(&self) -> bool {
        let mut events = self.events.lock().unwrap();
        loop {
            match events.next_event() {
                Ok(event) => dispatch(event),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return true,
                Err(_) => {
                    self.client.event_disconnected();
                    return false;
                }
            }
        }
    }
}
unsafe extern "C" fn receive_events(
    data: *mut libc::c_void,
    _fd: i32,
    _event: ffi::watcher_event_t,
) -> bool {
    // SAFETY: registered data is a State; Watcher::drop waits for this call.
    unsafe { &*data.cast::<State>() }.receive()
}

fn dispatch(event: api::Event) {
    // The watcher runs on charon's workers while the kernel interface is alive.
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
