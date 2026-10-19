// SPDX-License-Identifier: GPL-2.0-or-later
fn main() {
    let path = "io.ranet.Kernel.varlink";
    println!("cargo:rerun-if-changed={path}");
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("kernel.rs");
    varlink_generator::generate(
        &mut std::fs::File::open(path).unwrap(),
        &mut std::fs::File::create(out).unwrap(),
        false,
    )
    .unwrap();
}
