import argparse
import os
import tempfile
from typing import Any, Sequence, Tuple, Union

import apsw
import apsw.shell
import lief

SQLiteValue = Union[None, int, float, bytes, str]


class ElfHeaderModule(object):
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
        return schema, ElfHeaderTable(self.binaries)

    Connect = Create


class ElfHeaderTable(object):
    def __init__(self, binaries: list[lief.Binary]):
        self.binaries = binaries

    def BestIndex(
        self,
        constraints: Sequence[Tuple[int, int]],
        orderbys: Sequence[Tuple[int, int]],
    ) -> Any:
        return None

    def Open(self):
        return ElfHeaderCursor(self.binaries)

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


class ElfHeaderCursor(object):
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

    def Column(self, number: int) -> SQLiteValue:
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


def start():
    parser = argparse.ArgumentParser(
        prog="sqlelf",
        description="Analyze ELF files with the power of SQL",
        epilog="Brought to you with ♥ by Farid Zakaria",
    )
    parser.add_argument(
        "filenames", nargs="+", metavar="FILE", help="The ELF file to analyze"
    )

    args = parser.parse_args()
    for filename in args.filenames:
        if not lief.is_elf(filename):
            print(f"{filename} is not elf format")
            exit(1)

    binaries: list[lief.Binary] = [lief.parse(filename) for filename in args.filenames]

    # forward sqlite logs to logging module
    # apsw.ext.log_sqlite()
    # Now we create the connection
    databse_path = os.path.join(tempfile.mkdtemp(), "database")
    connection = apsw.Connection(databse_path)
    # register the vtable on connection con
    connection.createmodule("elf_header", ElfHeaderModule(binaries))
    # tell SQLite about the table
    connection.execute("create VIRTUAL table temp.elf_header USING elf_header()")
    shell = apsw.shell.Shell(db=connection)
    shell.cmdloop()
