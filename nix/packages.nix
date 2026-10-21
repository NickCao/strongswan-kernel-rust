{ pkgs }:
let
  inherit (pkgs) lib;
  version = (lib.importTOML ../Cargo.toml).package.version;
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../rust-toolchain.toml
      ../COPYING
      ../src
      ../plugin
      ../protocol
      (lib.fileset.fileFilter (file: file.hasExt "rs") ../tests)
    ];
  };
  toolchain = pkgs.rust-bin.fromRustupToolchainFile ../rust-toolchain.toml;
  rustPlatform = pkgs.makeRustPlatform {
    cargo = toolchain;
    rustc = toolchain;
  };

  # Keep upstream plugins and external plugins in the NixOS system profile.
  strongswan = pkgs.strongswan.overrideAttrs (old: {
    # Upstream uses Python to generate the installed plugin configuration snippets.
    nativeBuildInputs = old.nativeBuildInputs ++ [ pkgs.python3 ];
    # EAP is unused by ranet. Its helper libraries require libtool relinking,
    # which prevents overriding the plugin installation directory.
    configureFlags = lib.filter (flag: !(lib.hasPrefix "--enable-eap-" flag)) old.configureFlags ++ [
      "--with-plugindir=/run/current-system/sw/lib/ipsec/plugins"
      "--with-piddir=/run/strongswan"
    ];
    installFlags = old.installFlags ++ [
      "plugindir=${placeholder "out"}/lib/ipsec/plugins"
    ];
  });

  # Reuse the package's source, patches, dependencies and configure flags.
  # Only configuration runs; compiling strongSwan is unnecessary for bindgen.
  headers = strongswan.overrideAttrs (old: {
    pname = "strongswan-kernel-headers";
    outputs = [ "out" ];
    dontBuild = true;
    doCheck = false;
    doInstallCheck = false;
    dontFixup = true;
    installPhase = ''
      runHook preInstall
      find src/libstrongswan src/libcharon -type f -name '*.h' \
        -exec install -Dm644 '{}' "$out/{}" \;
      install -m644 config.h "$out/config.h"
      runHook postInstall
    '';
  });

  # Plugin installation mode requires cargo-c >= 0.10.26.
  cargoC = (pkgs.cargo-c.override { inherit rustPlatform; }).overrideAttrs (old: rec {
    version = "0.10.26";
    src = pkgs.fetchCrate {
      pname = "cargo-c";
      version = "${version}+cargo-0.100.0";
      hash = "sha256-rt7LegE5DEOF/BP7OCSkl8hcziUpz7dJr7kMNDwXw1c=";
    };
    cargoDeps = rustPlatform.fetchCargoVendor {
      inherit src;
      hash = "sha256-j4PIJnPy04vEzTPTo2aD5xMKLUTeyXt13+YdZaqCm2E=";
    };
  });

  cargoDeps = rustPlatform.importCargoLock { lockFile = ../Cargo.lock; };
  common = {
    inherit version src cargoDeps;
    meta = {
      description = "Rust kernel backend for strongSwan over tarpc";
      license = lib.licenses.gpl2Plus;
      platforms = lib.platforms.linux;
    };
  };

  daemon = rustPlatform.buildRustPackage (
    common
    // {
      pname = "charon-kernel-daemon";
      doCheck = false; # Run the complete Rust suite in the unit-tests VM check.
      cargoBuildFlags = [
        "-p"
        "charon-kernel-daemon"
      ];
      cargoTestFlags = [
        "-p"
        "charon-kernel-daemon"
        "-p"
        "kernel-rust-protocol"
      ];
      meta = common.meta // {
        mainProgram = "charon-kernel-daemon";
      };
    }
  );

  plugin = rustPlatform.buildRustPackage (
    common
    // {
      pname = "kernel-rust-plugin";
      nativeBuildInputs = [
        cargoC
        rustPlatform.bindgenHook
      ];
      # Included by strongSwan headers when configured with libcap support.
      buildInputs = [ pkgs.libcap ];
      STRONGSWAN_SOURCE = headers;
      CONFIG_H_DIR = headers;
      doCheck = false; # Host symbols are provided by charon; exercised in the VM test.
      buildPhase = ''
        runHook preBuild
        cargo cbuild -p strongswan-kernel-rust --release --offline --locked \
          --target ${pkgs.stdenv.hostPlatform.rust.rustcTarget} --library-type=cdylib
        runHook postBuild
      '';
      installPhase = ''
        runHook preInstall
        cargo cinstall -p strongswan-kernel-rust --release --offline --locked \
          --target ${pkgs.stdenv.hostPlatform.rust.rustcTarget} --library-type=cdylib \
          --prefix="$out" --libdir=lib
        runHook postInstall
      '';
    }
  );

  # The Rust test harness needs a real kernel and root for its isolated
  # namespaces. Keep this independent of the strongSwan NixOS integration test.
  unitTests = pkgs.vmTools.runInLinuxVM (
    daemon.overrideAttrs (_: {
      pname = "kernel-rust-tests";
      dontBuild = true; # cargo test builds the daemon and test executables itself.
      doCheck = true;
      cargoCheckType = "debug";
      enableParallelBuilding = true;
      memSize = 4096;
      nativeCheckInputs = [
        pkgs.iproute2
        pkgs.util-linux
        pkgs.kmod
      ];
      checkFlags = [
        "--include-ignored"
        "--test-threads=4"
      ];
      preCheck = ''
        # Nested KVM may choose the emulated ACPI clock. Use the paravirtual
        # clock when available, as in the strongSwan NixOS test.
        if grep -qw kvm-clock /sys/devices/system/clocksource/clocksource0/available_clocksource; then
          echo kvm-clock > /sys/devices/system/clocksource/clocksource0/current_clocksource
        fi
        modprobe -a ipv6 xfrm_user xfrm_interface esp4 esp6 xfrm_iptfs vrf dummy
      '';
      installPhase = "touch $out";
      dontFixup = true;
    })
  );

  kernelRust = pkgs.symlinkJoin {
    pname = "strongswan-kernel-rust";
    inherit version;
    paths = [
      daemon
      plugin
    ];
    passthru = {
      inherit
        strongswan
        headers
        daemon
        plugin
        ;
    };
    meta = common.meta // {
      mainProgram = "charon-kernel-daemon";
    };
  };
in
{
  inherit
    pkgs
    toolchain
    cargoC
    daemon
    plugin
    strongswan
    headers
    kernelRust
    unitTests
    ;
}
