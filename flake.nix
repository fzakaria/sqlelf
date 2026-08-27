{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = {
    self,
    nixpkgs,
  }: let
    supportedSystems = ["x86_64-linux" "x86_64-darwin" "aarch64-linux" "aarch64-darwin"];
    forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    nixpkgsFor = forAllSystems (system:
      import nixpkgs {
        inherit system;
        overlays = [
          self.overlay
        ];
      });
  in {
    overlay = final: prev: {
      sqlelf = prev.callPackage ./derivation.nix {};

      # Built through pkgsCross.gnu64 so the fixture is an x86_64-linux ELF no
      # matter which platform evaluates the flake. See tests/data/fixture.nix.
      sqlelf-test-fixture = prev.pkgsCross.gnu64.callPackage ./tests/data/fixture.nix {};
    };

    formatter = forAllSystems (system: (nixpkgsFor.${system}).alejandra);

    packages = forAllSystems (system:
      {
        default = (nixpkgsFor.${system}).sqlelf;
      }
      # Regenerating the fixture from a non-Linux host would mean building a
      # GNU cross toolchain from source, so only offer the package where it is
      # cheap. Every platform reads the committed artifact instead.
      // nixpkgs.lib.optionalAttrs (nixpkgs.lib.hasSuffix "-linux" system) {
        test-fixture = (nixpkgsFor.${system}).sqlelf-test-fixture;
      });

    devShells = forAllSystems (system:
      with nixpkgsFor.${system}; {
        default = mkShellNoCC {
          venvDir = "./.venv";
          # needed for tests
          TEST_BINARY = "${coreutils}/bin/ls";
          packages = [
            python3Packages.pip
            # This execute some shell code to initialize a venv in $venvDir before
            # dropping into the shell
            python3Packages.venvShellHook
          ];
          # bring all the dependencies needed to build sqlelf
          inputsFrom = [sqlelf];
          postVenvCreation = ''
            pip install --editable ".[dev]"
          '';
        };
      });
  };
}
