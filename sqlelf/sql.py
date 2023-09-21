import os
import sys
from typing import Any, Iterator

import apsw
import apsw.shell
import lief

from sqlelf import ldd
from sqlelf.elf import dynamic, header, instruction, section, strings, symbol
from dataclasses import dataclass


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


def make_sql_engine(binaries: list[lief.Binary], recursive=False) -> SQLEngine:
    connection = apsw.Connection(":memory:")

    if recursive:
        # We want to load all the shared libraries needed by each binary
        # so we can analyze them as well
        shared_libraries = [ldd.libraries(binary).values() for binary in binaries]
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

    header.register(connection, binaries)
    section.register(connection, binaries)
    symbol.register(connection, binaries)
    dynamic.register(connection, binaries)
    strings.register(connection, binaries)
    instruction.register(connection, binaries)
    return SQLEngine(connection)
