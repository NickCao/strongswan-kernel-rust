// SPDX-License-Identifier: GPL-2.0-or-later
use crate::{
    client::{Client, REGISTRY},
    ffi, ipsec, net,
};
use std::{ptr, sync::Arc};

#[repr(C)]
struct Plugin {
    public: ffi::plugin_t,
    client: Arc<Client>,
    features: [ffi::plugin_feature_t; 4],
}

// The loader expects a pointer-valued symbol, exactly as PLUGIN_DEFINE emits.
#[no_mangle]
pub static mut kernel_rust_plugin_version: *const libc::c_char = ffi::VERSION.as_ptr().cast();

#[no_mangle]
pub unsafe extern "C" fn kernel_rust_plugin_create() -> *mut ffi::plugin_t {
    unsafe {
        if !(*ffi::lib).get.unwrap()(ffi::lib, REGISTRY.as_ptr().cast_mut()).is_null() {
            return ptr::null_mut();
        }
        let Ok(client) = Client::create() else {
            return ptr::null_mut();
        };
        if !(*ffi::lib).set.unwrap()(
            ffi::lib,
            REGISTRY.as_ptr().cast_mut(),
            Arc::as_ptr(&client).cast_mut().cast(),
        ) {
            client.shutdown();
            return ptr::null_mut();
        }
        let plugin = Box::new(Plugin {
            public: ffi::plugin_t {
                get_name: Some(get_name),
                get_features: Some(get_features),
                reload: None,
                destroy: Some(destroy),
            },
            client,
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

unsafe extern "C" fn get_name(_this: *mut ffi::plugin_t) -> *mut libc::c_char {
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
    unsafe {
        (*ffi::lib).set.unwrap()(ffi::lib, REGISTRY.as_ptr().cast_mut(), ptr::null_mut());
        (*this.cast::<Plugin>()).client.shutdown();
        drop(Box::from_raw(this.cast::<Plugin>()));
    }
}
