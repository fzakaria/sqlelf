import argparse
import os
from functools import reduce

import apsw
import apsw.bestpractice
import apsw.shell
import lief

from .elf import dynamic, header, instruction, section, strings, symbol


def start():
    parser = argparse.ArgumentParser(
        prog="sqlelf",
        description="Analyze ELF files with the power of SQL",
        epilog="Brought to you with ♥ by Farid Zakaria",
    )
    parser.add_argument(
        "filenames", nargs="+", metavar="FILE", help="The ELF file to analyze"
    )
    parser.add_argument(
        "-s", "--sql", help="Potential SQL to execute. Omitting this enters the REPL."
    )

    args = parser.parse_args()

    # Iterate through our arguments and if one of them is a directory explode it out
    filenames: list[str] = reduce(
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
    apsw.bestpractice.apply(apsw.bestpractice.recommended)

    # Now we create the connection
    connection = apsw.Connection(":memory:")
    header.register(connection, binaries)
    section.register(connection, binaries)
    symbol.register(connection, binaries)
    dynamic.register(connection, binaries)
    strings.register(connection, binaries)
    instruction.register(connection, binaries)

    shell = apsw.shell.Shell(db=connection)

    if args.sql:
        shell.process_complete_line(args.sql)
    else:
        shell.cmdloop()
