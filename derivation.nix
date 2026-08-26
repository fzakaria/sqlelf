{
  lib,
  python3Packages,
  fetchPypi,
  zig,
  pyright,
}: let
  fs = lib.fileset;
in
  python3Packages.buildPythonApplication rec {
    name = "sqlelf";
    pyproject = true;

    SETUPTOOLS_SCM_PRETEND_VERSION = "0.0.0";

    src = fs.toSource {
      root = ./.;
      fileset = fs.unions [
        ./pyproject.toml
        ./tests
        ./sqlelf
        ./setup.cfg
        ./mypy.ini
        ./Makefile
        ./tools
        ./examples
        ./benchmarks
      ];
    };

    build-system = with python3Packages; [
      setuptools
      setuptools-scm
    ];

    dependencies = with python3Packages; [
      capstone
      lief
      apsw
      sh
    ];

    nativeCheckInputs = with python3Packages;
      [pytestCheckHook flake8 mypy isort black]
      ++ [pyright zig];

    postCheck = ''
      make lint
    '';

    meta = {
      homepage = "https://github.com/fzakaria/sqlelf";
      description = "Explore ELF objects through the power of SQL";
      license = lib.licenses.mit;
    };
  }
