#! /usr/bin/env python3
"""A benchmark to measure the time it takes to load a
    binary with a given number of functions.

Afterwards, run the file graph_symbol_size_benchmark.py to
generate a graph of the results."""
import pprint
import sqlite3
import subprocess
import tempfile
import timeit

from sqlelf import elf, sql


def create_executable_file(
    file: tempfile.NamedTemporaryFile, num_functions: int
) -> str:
    """Create an ELF executable file with a given number of functions"""
    functions = [
        f"""void function_{i}() {{ printf("Hello World {i}"); }}\n"""
        for i in range(num_functions)
    ]
    functions_str = "".join(functions)
    content = f"""
    #include <stdio.h>
    {functions_str}
    int main() {{ printf("Hello World!"); return 0; }}
    """
    file.write(content)
    file.flush()

    binary_name = tempfile.NamedTemporaryFile().name
    subprocess.run(["gcc", "-x", "c++", "-o", binary_name, file.name])
    return binary_name


def readelf_benchmark(binary_name: str, num_functions: int) -> None:
    result = subprocess.run(
        f"readelf -s {binary_name} | wc -l",
        capture_output=True,
        text=True,
        shell=True,
    )
    assert int(result.stdout) >= num_functions


def sqlelf_benchmark(binary_name: str, num_functions: int) -> None:
    sql_engine = sql.make_sql_engine([binary_name], cache_flags=elf.CacheFlag.SYMBOLS)
    result = list(sql_engine.execute("SELECT COUNT(*) as 'count' FROM ELF_SYMBOLS"))
    count = result[0]["count"]
    assert count >= num_functions


def sqlelf_memoized_benchmark(sqlite_database: str, num_functions: int) -> None:
    with sqlite3.connect(sqlite_database) as con:
        result = list(con.execute("SELECT COUNT(*) as 'count' FROM ELF_SYMBOLS"))
        count = result[0][0]
        assert count >= num_functions


data = {"Number of Functions": [], "sqlelf": [], "sqlelf-memoized": [], "readelf": []}

for exponent in range(1, 6):
    num_functions = 10**exponent
    data["Number of Functions"].append(num_functions)

    print(f"Number of functions: {num_functions}")  # noqa: T201
    # create the executable
    with tempfile.NamedTemporaryFile(mode="w") as file:
        file_name = file.name
        binary_file = create_executable_file(file, num_functions)
        data["readelf"].append(
            min(
                timeit.Timer(
                    lambda: readelf_benchmark(binary_file, num_functions)
                ).repeat(repeat=10, number=1)
            )
        )
        data["sqlelf"].append(
            timeit.timeit(
                lambda: sqlelf_benchmark(binary_file, num_functions), number=1
            )
        )

        sql_engine = sql.make_sql_engine(
            [binary_file], cache_flags=elf.CacheFlag.SYMBOLS
        )

        sqlite_database = tempfile.NamedTemporaryFile().name
        sql_engine.dump(sqlite_database)
        data["sqlelf-memoized"].append(
            min(
                timeit.Timer(
                    lambda: sqlelf_memoized_benchmark(sqlite_database, num_functions),
                ).repeat(repeat=10, number=1)
            )
        )

pprint.pprint(data)  # noqa: T203
