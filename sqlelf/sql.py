import os
import sys
from typing import Any, Iterator

import apsw
import apsw.shell
import lief

from sqlelf import ldd
from sqlelf.elf import dynamic, header, instruction, section, strings, symbol


class SQLEngine(object):
    def __init__(self, binaries: list[lief.Binary], recursive=False) -> None:
        self.connection = apsw.Connection(":memory:")

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

        header.register(self.connection, binaries)
        section.register(self.connection, binaries)
        symbol.register(self.connection, binaries)
        dynamic.register(self.connection, binaries)
        strings.register(self.connection, binaries)
        instruction.register(self.connection, binaries)

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
