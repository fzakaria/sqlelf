{ pkgs, ... }:

# The version of apsw in nixpkgs-unstable is a bit outdated.
# We bump it here but it also closely follows sqlite so we had to bump
# that as well.
let
  sqlite-3411 = pkgs.sqlite.overrideAttrs (oldAttrs: rec {
    version = "3.41.1";
    src = pkgs.fetchurl {
      url = "https://sqlite.org/2023/sqlite-autoconf-3410100.tar.gz";
      sha256 = "sha256-Ta376rn44WxpXU+7xRwWsvd/uX/0wcPROZGd/AOMnjM=";
    };
  });
  pythonPackageOverrides = self: super: {
    apsw = super.apsw.overridePythonAttrs (oldAttrs: rec {
      version = "3.41.0.1";
      src = pkgs.fetchFromGitHub {
        owner = "rogerbinns";
        repo = "apsw";
        # Use this custom commit with a fix for JOIN virtual table
        # until the next release
        rev = "ef2487eb5dcb75d2350fc91cb931ac4b196442a8";
        # rev = "refs/tags/${version}";
        sha256 = "sha256-xkFdTXARCP9RsrIJ/ZnlQwJo6g6mwWsH5WUHK0W7dkY=";
      };
      buildInputs = [
        sqlite-3411
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
