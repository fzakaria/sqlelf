{
  description = "sqlelf project flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    poetry2nix.url = "github:nix-community/poetry2nix";
  };

  outputs = {
    self,
    nixpkgs,
    poetry2nix,
  }: let
    supportedSystems = ["x86_64-linux" "x86_64-darwin" "aarch64-linux" "aarch64-darwin"];
    forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    pkgs = forAllSystems (system: nixpkgs.legacyPackages.${system});
  in {
    packages = forAllSystems (system: let
      inherit (poetry2nix.lib.mkPoetry2Nix {pkgs = pkgs.${system};}) mkPoetryApplication;
    in {
      default = mkPoetryApplication {projectDir = self;};
    });

    devShells = forAllSystems (system: let
      inherit (poetry2nix.lib.mkPoetry2Nix {pkgs = pkgs.${system};}) mkPoetryEnv;
    in {
      default = pkgs.${system}.mkShellNoCC {
        buildInputs = with pkgs.${system}; [
          gcc # LIEF requires libstdc++.so.6, which is available in gcc
        ];
        nativeBuildInputs = with pkgs.${system}; [
          autoPatchelfHook
        ];
        packages = with pkgs.${system}; [
          (mkPoetryEnv {
            # Define a Python environment that has only the dependencies listed
            # in the 'dev' and 'test' dependency groups of the pyproject.toml.
            groups = ["dev" "test"];
            projectDir = self;
          })
          coreboot-toolchain.riscv # cross-compiling toolchain for RISC-V
          mypy # static typing for Python
          poetry
          pyright # type checker for Python
          # qemu # machine & userspace emulator and virtualizer
        ];

        installPhase = ''
          runHook preInstall
          runHook postInstall
        '';

        shellHook = ''
          printf "=== sqlelf dev shell ===\n"
          echo "$(python --version)"
          echo "$(poetry --version)"
          echo "$(mypy --version)"
          echo "$(pyright --version)"

          # poetry install --without benchmarks

          export LD_LIBRARY_PATH=$(dirname $(find $(nix-store --query --references $(which gcc) | grep gcc | head -n 1) -name 'libstdc++.so.6'));
        '';
        # LIEF requires libstdc++.so.6, which is available in gcc but I think it
        # has to be patched with patchelf or autoPatchelfHook.
        # However, it seems autoPatchelfHook is not enough to make the linker
        # happy. Explicitly setting LD_LIBRARY_PATH is the only solution I was
        # able to find.
      };
    });
  };
}
