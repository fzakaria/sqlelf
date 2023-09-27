import os
import re
import sys
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Dict, Iterator, Optional, TextIO

import apsw
import apsw.shell
import lief
import sh  # type: ignore

from sqlelf import elf


@dataclass
class SQLEngine:
    connection: apsw.Connection

    def shell(self, stdin: TextIO = sys.stdin) -> apsw.shell.Shell:
        shell = apsw.shell.Shell(db=self.connection, stdin=stdin)
        shell.command_prompt(["sqlelf> "])  # type: ignore[no-untyped-call]
        return shell

    def execute_raw(
        self, sql: str, bindings: Optional["apsw.Bindings"] = None
    ) -> apsw.Cursor:
        return self.connection.execute(sql, bindings=bindings)

    def execute(
        self, sql: str, bindings: Optional["apsw.Bindings"] = None
    ) -> Iterator[dict[str, Any]]:
        cursor = self.execute_raw(sql, bindings=bindings)
        try:
            description = cursor.getdescription()
            column_names = [n for n, _ in description]
            for row in cursor:
                yield dict(zip(column_names, row))
        except apsw.ExecutionCompleteError:
            # This can happen if we LIMIT 0 or there are no results
            pass


def find_libraries(binary: lief.Binary) -> Dict[str, str]:
    """Use the interpreter in a binary to determine the path of each linked library"""
    interpreter = binary.interpreter  # type: ignore
    interpreter_cmd = sh.Command(interpreter)
    resolution = interpreter_cmd("--list", binary.name)
    result = OrderedDict()
    # TODO: Figure out why `--list` and `ldd` produce different outcomes
    # specifically for the interpreter.
    # https://gist.github.com/fzakaria/3dc42a039401598d8e0fdbc57f5e7eae
    for line in resolution.splitlines():  # type: ignore[unused-ignore]
        m = re.match(r"\s*([^ ]+) => ([^ ]+)", line)
        if not m:
            continue
        soname, lib = m.group(1), m.group(2)
        result[soname] = lib
    return result


def make_sql_engine(
    filenames: list[str],
    recursive: bool = False,
    cache_flags: elf.CacheFlag = elf.CacheFlag.INSTRUCTIONS | elf.CacheFlag.SYMBOLS,
) -> SQLEngine:
    """Create a SQL engine from a list of binaries

    You can make the SQL engine more speedy by only specifying the
    Generators (virtual tables) that you care about via the flags argument.
    The INSTRUCTIONS and SYMBOLS table are typically quite expensive to generate
    if they are not

    Args:
        filenames: the list of binaries to analyze -- should be absolute path
        recursive: whether to recursively load all shared
                libraries needed by each binary
        cache_flags: bit flag that controls which tables to cache
    """
    binaries: list[lief.Binary] = [
        lief.parse(filename) for filename in filenames if lief.is_elf(filename)
    ]
    connection = apsw.Connection(":memory:")

    if recursive:
        # We want to load all the shared libraries needed by each binary
        # so we can analyze them as well
        shared_libraries = [find_libraries(binary).values() for binary in binaries]
        # We want to readlink on the libraries to resolve
        # symlinks such as libm -> libc
        # also make this is a set in the case that multiple binaries use the same
        shared_libraries_set = set(
            [
                os.path.realpath(library)
                for sub_list in shared_libraries
                for library in sub_list
            ]
        )
        binaries = binaries + [lief.parse(library) for library in shared_libraries_set]

    elf.register_virtual_tables(connection, binaries, cache_flags)
    return SQLEngine(connection)
