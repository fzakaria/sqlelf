import argparse
import os
import tempfile
from functools import reduce

import apsw
import apsw.ext
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

    # Iterate through our arguments and if one of them is a directory explode it out
    filenames = reduce(
        lambda a, b: a + b,
        map(
            lambda dir: [os.path.join(dir, f) for f in os.listdir(dir)]
            if os.path.isdir(dir)
            else [dir],
            args.filenames,
        ),
    )
    # Filter the list of filenames to those that are ELF files only
    filenames = list(filter(lambda f: lief.is_elf(f), filenames))

    binaries: list[lief.Binary] = [lief.parse(filename) for filename in filenames]

    # forward sqlite logs to logging module
    apsw.ext.log_sqlite()
    # Now we create the connection
    databse_path = os.path.join(tempfile.mkdtemp(), "database")
    connection = apsw.Connection(databse_path)
    header.register(connection, binaries)
    shell = apsw.shell.Shell(db=connection)
    shell.cmdloop()
