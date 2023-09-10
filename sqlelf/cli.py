import argparse
import os
import os.path
import sys
from functools import reduce

import apsw
import apsw.bestpractice
import apsw.shell
import lief

from sqlelf import ldd

from .elf import dynamic, header, instruction, section, strings, symbol


def start(args=sys.argv[1:], stdin=sys.stdin):
    """
    Start the main CLI

    Args:
        args: the command line arguments to parse
        stdin: the stdin to use if invoking the shell
    """
    parser = argparse.ArgumentParser(
        prog="sqlelf",
        description="Analyze ELF files with the power of SQL",
        epilog="Brought to you with ♥ by Farid Zakaria",
    )
    parser.add_argument(
        "filenames", nargs="+", metavar="FILE", help="The ELF file to analyze"
    )
    parser.add_argument(
        "-s",
        "--sql",
        action="append",
        help="Potential SQL to execute. Omitting this enters the REPL.",
    )
    parser.add_argument(
        "--recursive",
        action=argparse.BooleanOptionalAction,
        help="Load all shared libraries needed by each file using ldd",
    )

    args = parser.parse_args(args)

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
    filenames = list(filter(lambda f: os.path.isfile(f) and lief.is_elf(f), filenames))

    # If none of the inputs are valid files, simply return
    if len(filenames) == 0:
        return

    binaries: list[lief.Binary] = [lief.parse(filename) for filename in filenames]

    # If the recursive option is specidied, load the shared libraries
    # the binary would load as well.
    if args.recursive:
        shared_libraries = [ldd.libraries(binary).values() for binary in binaries]
        # We want to readlink on the libraries to resolve symlinks such as libm -> libc
        # also make this is a set in the case that multiple binaries use the same
        shared_libraries = set(
            [
                os.path.realpath(library)
                for sub_list in shared_libraries
                for library in sub_list
            ]
        )
        binaries = binaries + [lief.parse(library) for library in shared_libraries]

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

    shell = apsw.shell.Shell(db=connection, stdin=stdin)
    shell.command_prompt(["sqlelf> "])

    if args.sql:
        for sql in args.sql:
            shell.process_complete_line(sql)
    else:
        shell.cmdloop()
