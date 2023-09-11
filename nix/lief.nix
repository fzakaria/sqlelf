# This is an unreleased version of Lief that fixes a bug when generates GNU notes
# https://github.com/lief-project/LIEF/commit/3414ded8cdcbd9705f7871c66c212b15cd74ea69
# Nixpkgs derivation was updated to change how lief was built since it no longer has setup.py
# in the root of the directory.
# For now, we copy the derivation until it's merged into nixpkgs we are tracking.
# https://github.com/NixOS/nixpkgs/pull/251414 
{ fetchFromGitHub, python, stdenv, cmake, ninja }:
let
  pyEnv = python.withPackages (ps: [ ps.setuptools ps.tomli ps.pip ps.setuptools ]);
in
stdenv.mkDerivation rec {
  pname = "lief";
  version = "0.14.0-3414ded";
  src = fetchFromGitHub {
    owner = "lief-project";
    repo = "LIEF";
    rev = "3414ded8cdcbd9705f7871c66c212b15cd74ea69";
    sha256 = "sha256-GJTj4w8HhAiC2bQAjEIqPw9feaOHL4fmAfLACioW0Q0=";
  };
  outputs = [ "out" "py" ];

  nativeBuildInputs = [
    cmake
    ninja
  ];

  # Not a propagatedBuildInput because only the $py output needs it; $out is
  # just the library itself (e.g. C/C++ headers).
  buildInputs = [
    python
  ];

  postBuild = ''
    pushd /build/source/api/python
    ${pyEnv.interpreter} setup.py build --parallel=$NIX_BUILD_CORES
    popd
  '';

  postInstall = ''
    pushd /build/source/api/python
    ${pyEnv.interpreter} setup.py install --skip-build --root=/ --prefix=$py
    popd
  '';
}
