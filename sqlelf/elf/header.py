# Without this Python was complaining
from __future__ import annotations

from typing import Any, Sequence, Tuple

import apsw
import apsw.ext
import lief


class Module(object):
    def __init__(self, binaries):
        self.binaries = binaries

    def Create(
        self,
        connection: apsw.Connection,
        modulename: str,
        databasename: str,
        tablename: str,
        *args,
    ):
        schema = "CREATE TABLE elf_header (path, type, machine, version, entry)"
        return schema, Table(self.binaries)

    Connect = Create


class Table(object):
    def __init__(self, binaries: list[lief.Binary]):
        self.binaries = binaries

    def BestIndex(
        self,
        constraints: Sequence[Tuple[int, int]],
        orderbys: Sequence[Tuple[int, int]],
    ) -> Any:
        return None

    def Open(self):
        return Cursor(self.binaries)

    def Disconnect(self):
        pass

    Destroy = Disconnect

    def UpdateChangeRow(self, rowid, newrowid, fields):
        pass

    def UpdateDeleteRow(self, rowid):
        pass

    def UpdateInsertRow(self, rowid, fields):
        # Return a rowid.
        pass


class Cursor(object):
    def __init__(self, binaries: list[lief.Binary]):
        self.binaries = binaries
        self.index = 0

    def Close(self):
        pass

    def Eof(self) -> bool:
        return self.index >= len(self.binaries)

    def Next(self):
        self.index += 1

    def Rowid(self):
        return self.index

    def Filter(
        self, indexnum: int, indexname: str, constraintargs: Tuple | None
    ) -> None:
        pass

    def Column(self, number: int) -> apsw.SQLiteValue:
        binary = self.binaries[self.index]
        columns = [
            binary.name,
            binary.header.file_type.value,
            binary.header.machine_type.value,
            binary.header.identity_version.value,
            binary.header.entrypoint,
        ]
        if number == -1:
            return 0
        if number >= len(columns):
            raise Exception(f"Unknown column number {number}")
        return columns[number]


def table_range(start=1, stop=100, step=1):
    for i in range(start, stop + 1, step):
        yield (i,)


# set column names
table_range.columns = ("value",)

# register it
apsw.ext.make_virtual_module(connection, "range", table_range)
