from sqlelf import sql
import lief
from unittest.mock import patch
import sh  # type: ignore


def test_simple_binary_real() -> None:
    binary = lief.parse("/bin/ls")
    result = sql.find_libraries(binary)
    assert len(result) > 0


@patch("sh.Command")
def test_simple_binary_mocked(Command: sh.Command) -> None:
    binary = lief.parse("/bin/ls")
    interpreter = binary.interpreter  # type: ignore
    expected_return_value = """
        linux-vdso.so.1 (0x00007ffc5d8ff000)
        /lib/x86_64-linux-gnu/libnss_cache.so.2 (0x00007f6995d92000)
        libselinux.so.1 => not found
        fake.so.6 => /some-path/fake.so.6
        libc.so.6 => /nix/store/46m4xx889wlhsdj72j38fnlyyvvvvbyb-glibc-2.37-8/lib/libc.so.6 (0x00007f6995bac000)
        /lib64/ld-linux-x86-64.so.2 => /nix/store/46m4xx889wlhsdj72j38fnlyyvvvvbyb-glibc-2.37-8/lib64/ld-linux-x86-64.so.2 (0x00007f6995dc1000)
    """
    Command(interpreter).return_value = expected_return_value  # pyright: ignore
    result = sql.find_libraries(binary)
    assert len(result) == 4
    assert result["fake.so.6"] == "/some-path/fake.so.6"
    assert (
        result["/lib64/ld-linux-x86-64.so.2"]
        == "/nix/store/46m4xx889wlhsdj72j38fnlyyvvvvbyb-glibc-2.37-8/lib64/ld-linux-x86-64.so.2"
    )
    assert (
        result["libc.so.6"]
        == "/nix/store/46m4xx889wlhsdj72j38fnlyyvvvvbyb-glibc-2.37-8/lib/libc.so.6"
    )
    # TODO(fzakaria):better handling for not found
    # kind of a weird one since this should never happen though
    assert result["libselinux.so.1"] == "not"


def test_simple_select_header() -> None:
    # TODO(fzakaria): Figure out a better binary to be doing that we control
    engine = sql.make_sql_engine(["/bin/ls"])
    result = list(engine.execute("SELECT * FROM elf_headers LIMIT 1"))
    assert len(result) == 1
    assert "path" in result[0]
    assert "type" in result[0]
    assert "version" in result[0]
    assert "machine" in result[0]
    assert "entry" in result[0]


def test_simple_select_version_requirements() -> None:
    # TODO(fzakaria): Figure out a better binary to be doing that we control
    engine = sql.make_sql_engine(["/bin/ls"])
    result = list(engine.execute("SELECT * FROM elf_version_requirements LIMIT 1"))
    assert len(result) == 1
    assert "path" in result[0]
    assert "file" in result[0]
    assert "name" in result[0]


def test_select_zero_rows() -> None:
    # TODO(fzakaria): Figure out a better binary to be doing that we control
    engine = sql.make_sql_engine(["/bin/ls"])
    result = list(engine.execute("SELECT * FROM elf_headers LIMIT 0"))
    assert len(result) == 0


def test_non_existent_file() -> None:
    engine = sql.make_sql_engine(["/doesnotexist"])
    result = list(engine.execute("SELECT * FROM elf_headers LIMIT 1"))
    assert len(result) == 0


def test_select_with_bindings() -> None:
    engine = sql.make_sql_engine(["/bin/ls", "/bin/cat"])
    result = list(
        engine.execute(
            """
            SELECT * FROM elf_version_requirements
            WHERE path = :path
            LIMIT 1
            """,
            {"path": "/bin/ls"},
        )
    )
    assert len(result) == 1
    assert "path" in result[0]
    assert result[0]["path"] == "/bin/ls"
    assert "file" in result[0]
    assert "name" in result[0]
