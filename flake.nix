{
  description = "Rust project";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nixpkgs.url = "nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ rust-overlay.overlays.default ];
        pkgs = import nixpkgs { inherit system overlays; };
        rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        inputs = [
            rust
            pkgs.rust-analyzer
            pkgs.pkg-config
            pkgs.openssl
            pkgs.zlib
            pkgs.gcc
            pkgs.clang
            pkgs.jq
            pkgs.runc
            pkgs.conmon
            pkgs.slirp4netns
            pkgs.fuse-overlayfs
        ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.libiconv
        ];
      in
      {
        defaultPackage = pkgs.rustPlatform.buildRustPackage {
          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          nativeBuildInputs = inputs;
        };


        devShell = pkgs.mkShell {
          packages = inputs;
          shellHook = ''
            export LIBCLANG_PATH=${pkgs.libclang.lib}/lib/
            export LD_LIBRARY_PATH=${pkgs.openssl}/lib:$LD_LIBRARY_PATH
            export CC_wasm32_unknown_unknown=${pkgs.llvmPackages_14.clang-unwrapped}/bin/clang-14
            export CFLAGS_wasm32_unknown_unknown="-I ${pkgs.llvmPackages_14.libclang.lib}/lib/clang/14.0.6/include/"
            export PKG_CONFIG_PATH=${pkgs.openssl.dev}/lib/pkgconfig

            export RUST_LOG=info
          '';
        };
      }
    );
}
