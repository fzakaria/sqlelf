from dataclasses import dataclass
from unittest.mock import patch

import pytest
import sh

from sqlelf import lief_ext, sql
from tests.binaries import ELF_FIXTURE, NATIVE_BINARY, can_resolve_libraries


@pytest.mark.skipif(
    not can_resolve_libraries(NATIVE_BINARY),
    reason=f"{NATIVE_BINARY} is not an ELF binary whose interpreter runs here",
)
def test_simple_binary_real() -> None:
    """Resolve the libraries of a host binary by really running its
    interpreter, which is the only test that needs a native ELF."""
    binary = lief_ext.Binary(NATIVE_BINARY)
    result = sql.find_libraries(binary)
    assert len(result) > 0


@patch("sh.Command")
def test_simple_binary_mocked(Command: sh.Command) -> None:
    """Parse the interpreter's --list output without running it, by mocking
    sh.Command out from under find_libraries."""
    binary = lief_ext.Binary(ELF_FIXTURE)
    interpreter = binary.interpreter
    expected_return_value = """
        linux-vdso.so.1 (0x00007ffc5d8ff000)
        /lib/x86_64-linux-gnu/libnss_cache.so.2 (0x00007f6995d92000)
        libselinux.so.1 => not found
        fake.so.6 => /some-path/fake.so.6
        libc.so.6 => /nix/store/46m4xx889wlhsdj72j38fnlyyvvvvbyb-glibc-2.37-8/lib/libc.so.6 (0x00007f6995bac000)
        /lib64/ld-linux-x86-64.so.2 => /nix/store/46m4xx889wlhsdj72j38fnlyyvvvvbyb-glibc-2.37-8/lib64/ld-linux-x86-64.so.2 (0x00007f6995dc1000)
    """  # noqa: E501
    Command(interpreter).return_value = expected_return_value  # type: ignore[attr-defined] # noqa: E501 # pyright: ignore
    result = sql.find_libraries(binary)
    assert len(result) == 4
    assert result["fake.so.6"] == "/some-path/fake.so.6"
    assert (
        result["/lib64/ld-linux-x86-64.so.2"]
        == "/nix/store/46m4xx889wlhsdj72j38fnlyyvvvvbyb-glibc-2.37-8/lib64/ld-linux-x86-64.so.2"  # noqa: E501
    )
    assert (
        result["libc.so.6"]
        == "/nix/store/46m4xx889wlhsdj72j38fnlyyvvvvbyb-glibc-2.37-8/lib/libc.so.6"
    )
    # TODO(fzakaria):better handling for not found
    # kind of a weird one since this should never happen though
    assert result["libselinux.so.1"] == "not"


def test_find_libraries_no_interpreter() -> None:
    """A statically linked binary has no interpreter to ask, so no libraries
    can be resolved."""
    binary = lief_ext.Binary(ELF_FIXTURE)
    binary.interpreter = ""
    result = sql.find_libraries(binary)
    assert len(result) == 0


def test_find_libraries_missing_interpreter() -> None:
    """An interpreter that is not on this machine resolves to no libraries
    rather than raising."""
    binary = lief_ext.Binary(ELF_FIXTURE)
    binary.interpreter = "/nix/store/something/ld-linux.so.2"
    result = sql.find_libraries(binary)
    assert len(result) == 0


def test_all_selects() -> None:
    """This test gets all the tables that should be created by sqlelf
    as they are prefixed with elf_ and tries to fetch all columns

    This is a pretty good way to get a quick exhausting test over all
    the functionality."""
    # Generate all the SELECT statements for us
    select_all_sql = """SELECT 'SELECT * FROM ' || name || ' LIMIT 1' as 'sql'
                        FROM sqlite_schema
                        WHERE (name LIKE 'elf_%' OR name LIKE 'dwarf_%')
                            AND type = 'table'"""
    engine = sql.make_sql_engine([ELF_FIXTURE])
    results = list(engine.execute(select_all_sql))
    assert len(results) > 0
    for result in results:
        assert len(list(engine.execute(result["sql"]))) == 1


@dataclass
class SimpleSQLTestCase:
    table: str
    columns: list[str]


def test_simple_selects() -> None:
    test_cases = [
        SimpleSQLTestCase(
            "elf_headers", ["path", "type", "version", "machine", "entry", "is_pie"]
        ),
        SimpleSQLTestCase(
            "elf_instructions",
            ["path", "section", "mnemonic", "address", "operands", "size"],
        ),
        SimpleSQLTestCase("elf_version_requirements", ["path", "file", "name"]),
    ]
    engine = sql.make_sql_engine([ELF_FIXTURE])
    for test_case in test_cases:
        result = list(engine.execute(f"SELECT * FROM {test_case.table} LIMIT 1"))
        assert len(result) == 1
        assert all(column in result[0] for column in test_case.columns)

        # also test selecting a LIMIT of 0 as that can require special handling
        result = list(engine.execute(f"SELECT * FROM {test_case.table} LIMIT 0"))
        assert len(result) == 0


def test_non_existent_file() -> None:
    engine = sql.make_sql_engine(["/doesnotexist"])
    result = list(engine.execute("SELECT * FROM elf_headers LIMIT 1"))
    assert len(result) == 0


def test_select_with_bindings() -> None:
    engine = sql.make_sql_engine([ELF_FIXTURE])
    result = list(
        engine.execute(
            """
            SELECT * FROM elf_version_requirements
            WHERE path = :path
            LIMIT 1
            """,
            {"path": ELF_FIXTURE},
        )
    )
    assert len(result) == 1
    assert "path" in result[0]
    assert result[0]["path"] == ELF_FIXTURE
    assert "file" in result[0]
    assert "name" in result[0]
