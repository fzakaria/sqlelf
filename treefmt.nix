# Formatter configuration shared by `nix fmt` and the `formatting` flake check.
#
# Every formatter here is pinned by flake.lock, which is the point: black's
# stable style changes between releases, so a floating `pip install black` in
# CI disagrees with whatever a contributor happens to have installed. Pinning
# makes formatting a single, reproducible answer.
_: let
  # Paths black and isort must not touch. They are excluded per-formatter
  # rather than globally because the treefmt in the pinned nixpkgs does not
  # read the top-level `excludes` key that `settings.global` writes.
  #
  # Note that black and isort are configured to skip these in pyproject.toml
  # too, but that only covers files they discover by walking a directory --
  # treefmt hands them explicit paths, which bypasses those settings.
  pythonExcludes = [
    # Vendored verbatim from pyelftools; reformatting it would only make the
    # next copybara import conflict.
    "sqlelf/_vendor/**"
    # Written by setuptools-scm at build time.
    "sqlelf/_version.py"
  ];
in {
  projectRootFile = "flake.nix";

  programs.alejandra.enable = true;
  programs.isort.enable = true;
  programs.black.enable = true;

  # isort rewrites the import block that black then wraps, so it runs first.
  settings.formatter.isort.priority = 0;
  settings.formatter.black.priority = 1;

  settings.formatter.isort.excludes = pythonExcludes;
  settings.formatter.black.excludes = pythonExcludes;
}
