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
    };

    formatter = forAllSystems (system: (nixpkgsFor.${system}).alejandra);

    packages = forAllSystems (system: {
      default = (nixpkgsFor.${system}).sqlelf;
    });

    devShells = forAllSystems (system:
      with nixpkgsFor.${system}; {
        default = mkShellNoCC {
          inputsFrom = [sqlelf];
          packages = [python3Packages.pip];
          shellHook = ''
            echo "Happy hacking."
          '';
        };
      });
  };
}
