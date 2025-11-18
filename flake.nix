{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    nixpkgs,
    flake-utils,
    rust-overlay,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [rust-overlay.overlays.default];
        };
        custom-rust-bin = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        rustPlatform = pkgs.makeRustPlatform {
          cargo = custom-rust-bin;
          rustc = custom-rust-bin;
        };

        build = pname: src:
          rustPlatform.buildRustPackage {
            inherit pname src;
            version = (builtins.fromTOML (builtins.readFile "${src}/Cargo.toml")).package.version;

            cargoLock = {
              lockFile = "${src}/Cargo.lock";
            };

            meta = {
              mainProgram = pname;
            };
          };
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            pkg-config
            openssl
          ];
          packages = [
            custom-rust-bin
          ];
        };

        packages.default = build "default" ./.;
      }
    );
}
