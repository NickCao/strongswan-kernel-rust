{
  description = "strongSwan kernel privilege separation with Rust and tarpc";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      builds = forAllSystems (
        system:
        import ./nix/packages.nix {
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
        }
      );
    in
    {
      packages = forAllSystems (system: {
        default = builds.${system}.kernelRust;
        charon-kernel-daemon = builds.${system}.daemon;
        kernel-rust-plugin = builds.${system}.plugin;
        strongswan = builds.${system}.strongswan;
        strongswan-headers = builds.${system}.headers;
      });

      nixosModules.default = import ./nix/module.nix self;

      checks = forAllSystems (system: {
        package = self.packages.${system}.default;
        unit-tests = builds.${system}.unitTests;
        end-to-end = builds.${system}.pkgs.testers.runNixOSTest (
          import ./nix/test.nix {
            inherit (builds.${system}) pkgs;
            package = builds.${system}.kernelRust;
            module = self.nixosModules.default;
          }
        );
      });

      devShells = forAllSystems (system: {
        default = builds.${system}.pkgs.mkShell {
          packages = with builds.${system}; [
            toolchain
            cargoC
            pkgs.pkg-config
            pkgs.rustPlatform.bindgenHook
          ];
          STRONGSWAN_SOURCE = builds.${system}.headers;
          CONFIG_H_DIR = builds.${system}.headers;
        };
      });

      formatter = forAllSystems (system: builds.${system}.pkgs.nixfmt-tree);
    };
}
