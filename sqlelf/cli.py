import argparse
import os
import tempfile

import apsw
import apsw.shell
import lief

from .elf import header


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
    connection.createmodule("elf_header", header.Module(binaries))
    # tell SQLite about the table
    connection.execute("create VIRTUAL table temp.elf_header USING elf_header()")
    shell = apsw.shell.Shell(db=connection)
    shell.cmdloop()
