// SPDX-License-Identifier: GPL-2.0-or-later
use crate::{events, ffi, host, ipsec, log, net};
use kernel_rust_protocol::client::Client;
use std::{
    ptr,
    sync::{Arc, Mutex, Weak},
};

// Constructors and the plugin are Rust code in the same module. Keep shared
// ownership in Rust, rather than storing an untyped Arc pointer in C's registry.
static CLIENT: Mutex<Weak<Client>> = Mutex::new(Weak::new());
pub fn current_client() -> Option<Arc<Client>> {
    CLIENT.lock().unwrap().upgrade()
}

#[repr(C)]
struct Plugin {
    public: ffi::plugin_t,
    client: Arc<Client>,
    events: events::EventJob,
    features: [ffi::plugin_feature_t; 4],
}

// The loader expects a pointer-valued symbol, exactly as PLUGIN_DEFINE emits.
#[no_mangle]
pub static mut kernel_rust_plugin_version: *const libc::c_char = ffi::VERSION.as_ptr().cast();

#[no_mangle]
pub unsafe extern "C" fn kernel_rust_plugin_create() -> *mut ffi::plugin_t {
    let mut slot = CLIENT.lock().unwrap();
    if slot.upgrade().is_some() {
        return ptr::null_mut();
    }
    // SAFETY: charon initializes lib/settings/processor before this entry point.
    let Ok(config) = (unsafe { host::config() }) else {
        return ptr::null_mut();
    };
    let client = match Client::connect(&config) {
        Ok(session) => session,
        Err(error) => {
            log(&format!("connecting to {} failed: {error}", config.path));
            return ptr::null_mut();
        }
    };
    // SAFETY: this plugin owns the registration and drops it before unload.
    let events = unsafe { events::EventJob::register(&client) };
    *slot = Arc::downgrade(&client);
    let plugin = Box::new(Plugin {
        public: ffi::plugin_t {
            get_name: Some(get_name),
            get_features: Some(get_features),
            reload: None,
            destroy: Some(destroy),
        },
        client,
        events,
        features: [
            callback(
                Some(ffi::kernel_ipsec_register),
                ipsec::create as *mut libc::c_void,
            ),
            provide(c"kernel-ipsec"),
            callback(
                Some(ffi::kernel_net_register),
                net::create as *mut libc::c_void,
            ),
            provide(c"kernel-net"),
        ],
    });
    Box::into_raw(plugin).cast()
}

fn callback(f: ffi::plugin_feature_callback_t, data: *mut libc::c_void) -> ffi::plugin_feature_t {
    let mut feature = ffi::plugin_feature_t {
        kind: ffi::plugin_feature_t_FEATURE_CALLBACK,
        type_: ffi::plugin_feature_t_FEATURE_NONE,
        ..Default::default()
    };
    feature.arg.cb = ffi::plugin_feature_t__bindgen_ty_3__bindgen_ty_4 { f, data };
    feature
}

fn provide(name: &std::ffi::CStr) -> ffi::plugin_feature_t {
    let mut feature = ffi::plugin_feature_t {
        kind: ffi::plugin_feature_t_FEATURE_PROVIDE,
        type_: ffi::plugin_feature_t_FEATURE_CUSTOM,
        ..Default::default()
    };
    feature.arg.custom = name.as_ptr().cast_mut();
    feature
}

extern "C" fn get_name(_this: *mut ffi::plugin_t) -> *mut libc::c_char {
    c"kernel-rust".as_ptr().cast_mut()
}

unsafe extern "C" fn get_features(
    this: *mut ffi::plugin_t,
    features: *mut *mut ffi::plugin_feature_t,
) -> i32 {
    // The host borrows this immutable array for the plugin's lifetime.
    unsafe {
        *features = ptr::addr_of_mut!((*this.cast::<Plugin>()).features).cast();
    }
    4
}

unsafe extern "C" fn destroy(this: *mut ffi::plugin_t) {
    // SAFETY: this is the exact pointer returned by our constructor, once only.
    let plugin = unsafe { Box::from_raw(this.cast::<Plugin>()) };
    *CLIENT.lock().unwrap() = Weak::new();
    // Stop and join event callbacks before closing the shared session.
    drop(plugin.events);
    if let Err(error) = plugin.client.close() {
        log(&error.to_string());
    }
}
