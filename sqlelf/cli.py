import argparse
import logging
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
    cache_flag: elf.CacheFlag = elf.CacheFlag.ALL()


def cache_flag_type(str: str) -> elf.CacheFlag:
    """Split a comma separated list of cache flags into a single cache flag"""
    flag_names = str.split(",")
    flag = elf.CacheFlag.NONE
    for name in flag_names:
        flag |= elf.CacheFlag.from_string(name.strip().upper())
    return flag


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

    default_cache_flag_str = (
        str(elf.CacheFlag.ALL()).replace("CacheFlag.", "").replace("|", ",")
    )
    parser.add_argument(
        "--cache-flag",
        type=cache_flag_type,
        default=elf.CacheFlag.ALL(),
        help=f"""A comma-separated list of flags to set which control caching.
            Default is ALL which is shorthand for {default_cache_flag_str}""",
    )

    program_args: ProgramArguments = parser.parse_args(
        args, namespace=ProgramArguments()
    )

    # Iterate through our arguments and if one of them is a directory explode it out
    # Assuming program_args.filenames is a list of files and directories
    filenames: list[str] = reduce(
        lambda a, b: a + b,
        map(
            lambda dir: (
                [
                    os.path.join(root, file)
                    for root, _, files in os.walk(dir)
                    for file in files
                ]
                if os.path.isdir(dir)
                else [dir]
            ),
            program_args.filenames,
        ),
    )
    # Filter the list of filenames to those that are files only
    filenames = [f for f in filenames if os.path.isfile(f)]

    # If none of the inputs are valid files, simply return
    if len(filenames) == 0:
        sys.exit("No valid ELF files were provided")

    # Setup the logging config
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s",
    )

    sql_engine = api_sql.make_sql_engine(
        filenames, recursive=program_args.recursive, cache_flags=program_args.cache_flag
    )
    shell = sql_engine.shell(stdin=stdin)

    if program_args.sql and len(program_args.filenames) > 0:
        for sql in program_args.sql:
            shell.process_complete_line(sql)  # type: ignore[no-untyped-call]
    else:
        shell.cmdloop()  # type: ignore[no-untyped-call]
