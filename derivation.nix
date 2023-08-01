let
  pkgs = import <nixpkgs> { };
in
with pkgs;
python3.pkgs.buildPythonPackage rec {
  name = "sqlelf";
  src = pkgs.nix-gitignore.gitignoreSource [ ] ./.;

  format = "pyproject";

  propagatedBuildInputs = with python3.pkgs; [
    setuptools
    apsw
    lief
    capstone
  ];

}
