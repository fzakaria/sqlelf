import argparse
import logging
import os
import sys
from dataclasses import dataclass, field
from typing import TextIO

import apsw


@dataclass
class ProgramArguments:
    filenames: list[str] = field(default_factory=list)
    output: str = "output.sqlite"


def is_sqlite_file(file: str) -> bool:
    """Tests if the given file is a valid SQLite file"""
    try:
        with apsw.Connection(file):
            return True
    except apsw.NotADBError:
        return False


def start(args: list[str] = sys.argv[1:], stdin: TextIO = sys.stdin) -> None:
    """
    Start the merge CLI

    Args:
        args: the command line arguments to parse
        stdin: the stdin to use if invoking the shell
    """
    # Setup the logging config
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s",
    )

    parser = argparse.ArgumentParser(
        prog="sqlelf-merge",
        description="Merge multiple sqlelf SQLITE databases into a single one.",
        epilog="Brought to you with ♥ by Farid Zakaria",
    )
    parser.add_argument(
        "filenames", nargs="+", metavar="FILE", help="The sqlites file to merge"
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output file to write the sqlite merged database to.",
    )

    program_args: ProgramArguments = parser.parse_args(
        args, namespace=ProgramArguments()
    )

    if not all([os.path.isfile(f) for f in program_args.filenames]):
        sys.exit("A provided file does not exist.")

    if not all([is_sqlite_file(f) for f in program_args.filenames]):
        sys.exit("A provided file is not a valid SQLite file.")

    # Take the first file to be the "canonical" database to fetch the list of tables
    # TODO(fzakaria): Consider listing from elf.py instead
    tables = []
    with apsw.Connection(program_args.filenames[0]) as conn:
        for row in conn.execute(
            """SELECT name
                        FROM sqlite_schema
                        WHERE (name LIKE 'elf_%' OR name LIKE 'dwarf_%')
                            AND type = 'table'"""
        ):
            tables.append(row[0])

    with apsw.Connection(program_args.output) as conn:
        # Attach all the databases
        for idx, file in enumerate(program_args.filenames):
            conn.execute(f"ATTACH DATABASE '{file}' AS DB{idx};")

        for table in tables:
            sql_union = [
                f"SELECT * FROM DB{idx}.{table}"
                for idx in range(len(program_args.filenames))
            ]

            sql = f"""
            CREATE TABLE {table} AS
            """ + " UNION ALL ".join(
                sql_union
            )
            conn.execute(sql)


if __name__ == "__main__":
    start()
