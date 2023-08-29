{ pkgs, ... }:

# The version of apsw in nixpkgs-unstable is a bit outdated.
# We bump it here but it also closely follows sqlite so we had to bump
# that as well.
let
  sqlite-3430 = pkgs.sqlite.overrideAttrs (oldAttrs: rec {
    version = "3.43.0";
    src = pkgs.fetchurl {
      url = "https://sqlite.org/2023/sqlite-autoconf-3430000.tar.gz";
      sha256 = "sha256-SQCNvzr8BNTtyOz8NOTq0ZaXMDQpPJl62tL2PwF2KuE=";
    };
  });
  pythonPackageOverrides = self: super: {
    apsw = super.apsw.overridePythonAttrs (oldAttrs: rec {
      version = "3.43.0.0";
      src = pkgs.fetchFromGitHub {
        owner = "rogerbinns";
        repo = "apsw";
        rev = "refs/tags/${version}";
        sha256 = "sha256-e5glVSAuHElDAarF7xvasBq8UY7n/J5bb3zSjT4fTuA=";
      };
      buildInputs = [
        sqlite-3430
      ];
    });
  };
in
{
  # See full reference at https://devenv.sh/reference/options/
  # https://devenv.sh/basics/
  env.GREET = "sqlelf devenv";

  # https://devenv.sh/packages/
  packages = with pkgs; [ git pyright nixpkgs-fmt shellcheck ];

  languages.python = {
    enable = true;
    venv.enable = true;
    package = (pkgs.python3.override {
      packageOverrides = pythonPackageOverrides;
    }).withPackages (ps: with ps; [ capstone apsw lief black isort flake8 ]);
  };

  # https://devenv.sh/integrations/codespaces-devcontainer/
  devcontainer.enable = true;

  # https://devenv.sh/pre-commit-hooks/
  pre-commit.hooks = {
    nixpkgs-fmt.enable = true;
    shellcheck.enable = true;
    black.enable = true;
  };

}
