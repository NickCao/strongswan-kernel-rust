// SPDX-License-Identifier: GPL-2.0-or-later
use std::{env, path::PathBuf};

fn main() {
    for name in ["STRONGSWAN_SOURCE", "CONFIG_H_DIR"] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let source = PathBuf::from(
        env::var_os("STRONGSWAN_SOURCE")
            .expect("set STRONGSWAN_SOURCE to the source tree matching the installed strongSwan"),
    );
    let config_dir = env::var_os("CONFIG_H_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| source.clone());
    assert!(
        source.is_absolute() && config_dir.is_absolute(),
        "STRONGSWAN_SOURCE and CONFIG_H_DIR must be absolute paths"
    );
    for header in ["src/libstrongswan/library.h", "src/libcharon/daemon.h"] {
        assert!(
            source.join(header).is_file(),
            "STRONGSWAN_SOURCE must contain the full strongSwan source tree; missing {}",
            source.join(header).display()
        );
    }
    let config = config_dir.join("config.h");
    assert!(
        config.is_file(),
        "CONFIG_H_DIR must contain the matching config.h; missing {}",
        config.display()
    );
    println!("cargo:rerun-if-changed={}", config.display());
    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_args(["-include", config.to_str().unwrap()])
        .allowlist_type("kernel_.*|plugin_.*|host_t|traffic_selector_t|library_t|daemon_t")
        .allowlist_function("kernel_(ipsec|net)_register|host_create_from_sockaddr|traffic_selector_create_from_bytes|callback_job_create_with_prio")
        .allowlist_var("lib|charon|dbg|VERSION|KERNEL_SPI_(MIN|MAX)|CPU_ID_MAX")
        .generate_comments(false)
        .layout_tests(false)
        .derive_debug(false)
        .derive_default(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));
    for subdir in ["src/libstrongswan", "src/libcharon"] {
        builder = builder.clang_arg(format!("-I{}", source.join(subdir).display()));
    }
    let bindings = builder
        .generate()
        .expect("generate matching strongSwan ABI");
    bindings
        .write_to_file(PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("bindings.rs"))
        .unwrap();
}
