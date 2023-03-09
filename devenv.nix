{ pkgs, ... }:

{
  # See full reference at https://devenv.sh/reference/options/
  # https://devenv.sh/basics/
  env.GREET = "devenv";

  # https://devenv.sh/packages/
  packages = [ pkgs.git ];

  languages.python = {
    enable = true;
    venv.enable = true;
    package = pkgs.python3.withPackages (ps: with ps; [ apsw ]);
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
