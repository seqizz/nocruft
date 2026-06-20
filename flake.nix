{
  description = "nocruft: trace filesystem creations under nix-shell via eBPF";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let
      # The NixOS module is system-agnostic. It picks up the package built
      # for the host's system from `self.packages.<system>.default`.
      nocruftModule = { config, pkgs, lib, ... }:
        let cfg = config.programs.nocruft;
        in {
          options.programs.nocruft = {
            enable = lib.mkEnableOption ''
              nocruft: an eBPF wrapper around nix-shell that reports
              filesystem paths created by the shell's process tree.
              Enabling installs the binary and creates a setcap wrapper
              with CAP_BPF + CAP_PERFMON under /run/wrappers/bin/nocruft.
            '';

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
              defaultText = lib.literalExpression
                "nocruft.packages.\${system}.default";
              description = "The nocruft package to install.";
            };
          };

          config = lib.mkIf cfg.enable {
            assertions = [{
              assertion = pkgs.stdenv.hostPlatform.system == "x86_64-linux";
              message = "nocruft currently only supports x86_64-linux.";
            }];

            environment.systemPackages = [ cfg.package ];

            # /run/wrappers/bin is on PATH for users by default on NixOS.
            # The wrapper carries the file capabilities, leaving the
            # underlying binary in the Nix store unprivileged.
            security.wrappers.nocruft = {
              owner = "root";
              group = "root";
              capabilities = "cap_bpf,cap_perfmon+ep";
              source = "${cfg.package}/bin/nocruft";
            };
          };
        };
    in
    (flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # Unwrapped clang: the nix cc-wrapper injects hardening flags
        # (-fzero-call-used-regs etc.) that the bpf clang target rejects.
        clangUnwrapped = pkgs.llvmPackages.clang-unwrapped;

        commonNativeBuildInputs = with pkgs; [
          clangUnwrapped
          llvmPackages.libllvm
          pkg-config
          bpftools
        ];

        commonBuildInputs = with pkgs; [
          libbpf
          elfutils
          zlib
        ];
      in {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "nocruft";
          version = "0.0.1";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          nativeBuildInputs = commonNativeBuildInputs;
          buildInputs = commonBuildInputs;

          preBuild = ''
            export CLANG=${clangUnwrapped}/bin/clang
          '';

          meta = with pkgs.lib; {
            description = "Trace filesystem creations under nix-shell via eBPF";
            license = licenses.gpl3Only;
            platforms = [ "x86_64-linux" ];
            mainProgram = "nocruft";
          };
        };

        apps.default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/nocruft";
        };

        devShells.default = pkgs.mkShell {
          name = "nocruft-dev";
          nativeBuildInputs = commonNativeBuildInputs ++ (with pkgs; [
            rustc
            cargo
            rustfmt
            clippy
            rust-analyzer
          ]);
          buildInputs = commonBuildInputs;

          LIBBPF_SYS_LIBRARY_PATH = "${pkgs.libbpf}/lib";
          PKG_CONFIG_PATH = pkgs.lib.concatStringsSep ":" [
            "${pkgs.libbpf}/lib/pkgconfig"
            "${pkgs.zlib.dev}/lib/pkgconfig"
            "${pkgs.elfutils.dev}/lib/pkgconfig"
          ];
        };
      })) // {
        nixosModules.default = nocruftModule;
        nixosModules.nocruft = nocruftModule;
      };
}
