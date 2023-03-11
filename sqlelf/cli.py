import argparse
import os
import tempfile
from typing import Sequence, Tuple, Union, Any

import apsw
import apsw.shell
import lief

SQLiteValue = Union[None, int, float, bytes, str]


class ElfHeaderModule(object):
    def __init__(self, binary):
        self.binary = binary

    def Create(
        self,
        connection: apsw.Connection,
        modulename: str,
        databasename: str,
        tablename: str,
        *args,
    ):
        schema = "CREATE TABLE elf_header (type, machine, version, entry)"
        return schema, ElfHeaderTable(self.binary)

    Connect = Create


class ElfHeaderTable(object):
    def __init__(self, binary: lief.Binary):
        self.binary = binary

    def BestIndex(
        self,
        constraints: Sequence[Tuple[int, int]],
        orderbys: Sequence[Tuple[int, int]],
    ) -> Any:
        return None

    def Open(self):
        return SingleRowCursor(self.binary)

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


class SingleRowCursor(object):
    def __init__(self, binary: lief.Binary):
        self.binary = binary
        self.closed = False

    def Close(self):
        pass

    def Eof(self) -> bool:
        return self.closed

    def Next(self):
        self.closed = True

    def Rowid(self):
        return 0

    def Filter(
        self, indexnum: int, indexname: str, constraintargs: Tuple | None
    ) -> None:
        pass

    def Column(self, number: int) -> SQLiteValue:
        match number:
            # Return the rowid which should always be 0
            case -1:
                return 0
            case 0:
                return self.binary.header.file_type.value
            case 1:
                return self.binary.header.machine_type.value
            case 2:
                return self.binary.header.identity_version.value
            case 3:
                return self.binary.header.entrypoint
            case _:
                raise Exception(f"Unknown column number {number}")


def start():
    parser = argparse.ArgumentParser(
        prog="sqlelf",
        description="Analyze ELF files with the power of SQL",
        epilog="Brought to you with ♥ by Farid Zakaria",
    )
    parser.add_argument("filename", metavar="FILE", help="The ELF file to analyze")
    args = parser.parse_args()

    if not lief.is_elf(args.filename):
        print(f"{args.filename} is not elf format")
        exit(1)

    binary: lief.Binary = lief.parse(args.filename)

    # forward sqlite logs to logging module
    # apsw.ext.log_sqlite()
    # Now we create the connection
    databse_path = os.path.join(tempfile.mkdtemp(), "database")
    connection = apsw.Connection(databse_path)
    # register the vtable on connection con
    connection.createmodule("elf_header", ElfHeaderModule(binary))
    # tell SQLite about the table
    connection.execute("create VIRTUAL table temp.elf_header USING elf_header()")
    shell = apsw.shell.Shell(db=connection)
    shell.cmdloop()
