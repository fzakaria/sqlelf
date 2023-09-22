import os
import re
import sys
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Dict, Iterator

import apsw
import apsw.shell
import lief
import sh  # type: ignore

from sqlelf import elf


@dataclass
class SQLEngine:
    connection: apsw.Connection

    def shell(self, stdin=sys.stdin) -> apsw.shell.Shell:
        shell = apsw.shell.Shell(db=self.connection, stdin=stdin)
        shell.command_prompt(["sqlelf> "])
        return shell

    def execute_raw(self, sql: str) -> apsw.Cursor:
        return self.connection.execute(sql)

    def execute(self, sql: str) -> Iterator[dict[str, Any]]:
        cursor = self.execute_raw(sql)
        description = cursor.getdescription()
        column_names = [n for n, _ in description]
        for row in cursor:
            yield dict(zip(column_names, row))


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


def make_sql_engine(binaries: list[lief.Binary], recursive=False) -> SQLEngine:
    connection = apsw.Connection(":memory:")

    if recursive:
        # We want to load all the shared libraries needed by each binary
        # so we can analyze them as well
        shared_libraries = [find_libraries(binary).values() for binary in binaries]
        # We want to readlink on the libraries to resolve
        # symlinks such as libm -> libc
        # also make this is a set in the case that multiple binaries use the same
        shared_libraries = set(
            [
                os.path.realpath(library)
                for sub_list in shared_libraries
                for library in sub_list
            ]
        )
        binaries = binaries + [lief.parse(library) for library in shared_libraries]

    elf.register_virtual_tables(connection, binaries)
    return SQLEngine(connection)
