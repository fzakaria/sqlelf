"""The binaries the test-suite reads, and the guards for using them.

Two different kinds of binary are needed:

* ELF_FIXTURE is a small ELF file committed to the repository. Every test that
  only *parses* an ELF file uses it, so those tests run identically on Linux,
  macOS and anywhere else lief is available.
* NATIVE_BINARY belongs to the host. Only the tests that actually *execute* the
  ELF interpreter to resolve shared libraries need it, and those tests are
  skipped when the host has no ELF binary they can run.
"""

import os

from sqlelf import lief_ext

# The committed fixture; see tests/data/fixture.nix for how it is regenerated.
ELF_FIXTURE = os.path.join(os.path.dirname(__file__), "data", "hello-x86_64.elf")

# Overridable so a packager can point the interpreter-executing tests at a
# binary that is guaranteed to be present in the build sandbox.
NATIVE_BINARY = os.getenv("TEST_BINARY", "/bin/ls")


def can_resolve_libraries(path: str) -> bool:
    """Whether sql.find_libraries can resolve shared libraries for `path`.

    find_libraries shells out to the ELF interpreter, so the file has to be an
    ELF binary, has to be dynamically linked, and its interpreter has to exist
    and be executable on this host. None of that holds for a Mach-O binary on
    macOS, nor for a foreign-architecture ELF such as the committed fixture.
    """
    if not os.path.exists(path) or not lief_ext.Binary.is_elf(path):
        return False

    interpreter = lief_ext.Binary(path).interpreter
    return bool(interpreter) and os.access(interpreter, os.X_OK)
