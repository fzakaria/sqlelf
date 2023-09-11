from sqlelf import ldd
from sqlelf.elf.binary import Binary
from unittest.mock import patch

def test_simple_binary_real():
    binary = Binary("/bin/ls")
    result = ldd.libraries(binary)
    assert len(result) > 0


@patch("sh.Command")
def test_simple_binary_mocked(Command):
    binary = Binary("/bin/ls")
    Command(binary.interpreter).return_value = """
    linux-vdso.so.1 (0x00007ffc5d8ff000)
	/lib/x86_64-linux-gnu/libnss_cache.so.2 (0x00007f6995d92000)
	libselinux.so.1 => not found
    fake.so.6 => /some-path/fake.so.6
	libc.so.6 => /nix/store/46m4xx889wlhsdj72j38fnlyyvvvvbyb-glibc-2.37-8/lib/libc.so.6 (0x00007f6995bac000)
	/lib64/ld-linux-x86-64.so.2 => /nix/store/46m4xx889wlhsdj72j38fnlyyvvvvbyb-glibc-2.37-8/lib64/ld-linux-x86-64.so.2 (0x00007f6995dc1000)
"""
    result = ldd.libraries(binary)
    assert len(result) == 4
    assert result["fake.so.6"] == "/some-path/fake.so.6"
    assert result["/lib64/ld-linux-x86-64.so.2"] == "/nix/store/46m4xx889wlhsdj72j38fnlyyvvvvbyb-glibc-2.37-8/lib64/ld-linux-x86-64.so.2"
    assert result["libc.so.6"] == "/nix/store/46m4xx889wlhsdj72j38fnlyyvvvvbyb-glibc-2.37-8/lib/libc.so.6"
    # TODO(fzakaria):better handling for not found
    # kind of a weird one since this should never happen though
    assert result["libselinux.so.1"] == "not"