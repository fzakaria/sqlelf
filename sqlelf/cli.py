import argparse
import os
import os.path
import sys
from dataclasses import dataclass, field
from functools import reduce
from typing import TextIO

from sqlelf import elf
from sqlelf import sql as api_sql


@dataclass
class ProgramArguments:
    filenames: list[str] = field(default_factory=list)
    sql: list[str] = field(default_factory=list)
    recursive: bool = False


def start(args: list[str] = sys.argv[1:], stdin: TextIO = sys.stdin) -> None:
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

    program_args: ProgramArguments = parser.parse_args(
        args, namespace=ProgramArguments()
    )

    # Iterate through our arguments and if one of them is a directory explode it out
    filenames: list[str] = reduce(
        lambda a, b: a + b,
        map(
            lambda dir: [os.path.join(dir, f) for f in os.listdir(dir)]
            if os.path.isdir(dir)
            else [dir],
            program_args.filenames,
        ),
    )
    # Filter the list of filenames to those that are files only
    filenames = [f for f in filenames if os.path.isfile(f)]

    # If none of the inputs are valid files, simply return
    if len(filenames) == 0:
        sys.exit("No valid ELF files were provided")

    sql_engine = api_sql.make_sql_engine(
        filenames, recursive=program_args.recursive, cache_flags=elf.CacheFlag.ALL()
    )
    shell = sql_engine.shell(stdin=stdin)

    if program_args.sql and len(program_args.filenames) > 0:
        for sql in program_args.sql:
            shell.process_complete_line(sql)  # type: ignore[no-untyped-call]
    else:
        shell.cmdloop()  # type: ignore[no-untyped-call]
