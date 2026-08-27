# Builds the ELF fixture that the test-suite parses.
#
# The output is committed to the repository as tests/data/hello-x86_64.elf so
# that hosts which have no ELF binaries of their own -- macOS, most obviously
# -- can still run every parsing test without needing a cross toolchain.
# Regenerate with `make fixture`.
#
# The compiler comes from `pkgsCross.gnu64`, so the fixture is always an
# x86_64-linux ELF no matter which platform builds it. On x86_64-linux that
# cross set degenerates to the native one and costs nothing; on macOS it means
# building a GNU cross toolchain from source, which is why the artifact is
# committed rather than built during the test run.
{
  stdenv,
  patchelf,
}:
stdenv.mkDerivation {
  name = "sqlelf-test-fixture";

  src = ./hello.c;
  dontUnpack = true;

  nativeBuildInputs = [patchelf];

  buildPhase = ''
    runHook preBuild

    # Pin the interpreter to the canonical distro path rather than whatever the
    # Nix toolchain would bake in, and drop the build-id so the artifact does
    # not churn between toolchain revisions.
    $CC -Os \
      -Wl,--build-id=none \
      -Wl,--dynamic-linker=/lib64/ld-linux-x86-64.so.2 \
      -o hello-x86_64.elf $src

    # The Nix toolchain adds a RUNPATH into the store, which would be dead
    # weight in a fixture that is committed and read on other machines.
    patchelf --remove-rpath hello-x86_64.elf

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    install -Dm444 hello-x86_64.elf $out/hello-x86_64.elf
    runHook postInstall
  '';
}
