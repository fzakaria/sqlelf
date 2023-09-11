{
  description = "Explore ELF objects through the power of SQL";
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.05";
    poetry2nix = {
      url = "github:nix-community/poetry2nix";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };
  };

  outputs = { self, nixpkgs, flake-utils, poetry2nix }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ poetry2nix.overlay (import ./nix/overlay.nix) ];
        };
      in
      {
        packages = {
          sqlelf = pkgs.sqlelf;
          default = pkgs.sqlelf;
        };

        devShell = pkgs.sqlelf-env.env.overrideAttrs
          (oldAttrs: { buildInputs = with pkgs; [ poetry nixpkgs-fmt ]; });
      });
}
