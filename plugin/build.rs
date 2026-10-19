// SPDX-License-Identifier: GPL-2.0-or-later
use std::{env, path::PathBuf};

fn main() {
    for name in ["STRONGSWAN_SOURCE", "STRONGSWAN_BUILD", "IPSEC_PIDDIR"] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let source = PathBuf::from(
        env::var_os("STRONGSWAN_SOURCE")
            .expect("set STRONGSWAN_SOURCE to the source tree matching the installed strongSwan"),
    );
    let build = env::var_os("STRONGSWAN_BUILD")
        .map(PathBuf::from)
        .unwrap_or_else(|| source.clone());
    assert!(
        source.is_absolute() && build.is_absolute(),
        "SDK paths must be absolute"
    );
    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_args(["-include", build.join("config.h").to_str().unwrap()])
        .allowlist_type("kernel_.*|plugin_.*|host_t|traffic_selector_t|library_t|daemon_t")
        .allowlist_function("kernel_(ipsec|net)_register|host_create_from_string|traffic_selector_create_from_bytes")
        .allowlist_var("lib|charon|dbg|VERSION|KERNEL_SPI_(MIN|MAX)|CPU_ID_MAX")
        .generate_comments(false)
        .layout_tests(false)
        .derive_debug(false)
        .derive_default(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));
    for tree in [&build, &source] {
        for subdir in ["src/libstrongswan", "src/libcharon"] {
            builder = builder.clang_arg(format!("-I{}", tree.join(subdir).display()));
        }
    }
    let bindings = builder
        .generate()
        .expect("generate matching strongSwan ABI");
    bindings
        .write_to_file(PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("bindings.rs"))
        .unwrap();
    let piddir = env::var("IPSEC_PIDDIR").unwrap_or_else(|_| "/run".into());
    assert!(piddir.starts_with('/') && !piddir.contains('\0'));
    println!("cargo:rustc-env=KERNEL_RUST_SOCKET={piddir}/charon-kernel.sock");
}
