import argparse
import os
import os.path
import sys
from functools import reduce

import lief

from sqlelf import sql as api_sql


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
        sys.exit("No valid ELF files were provided")

    binaries: list[lief.Binary] = [lief.parse(filename) for filename in filenames]

    sql_engine = api_sql.SQLEngine(binaries, recursive=args.recursive)
    shell = sql_engine.shell(stdin=stdin)

    if args.sql:
        for sql in args.sql:
            shell.process_complete_line(sql)
    else:
        shell.cmdloop()
