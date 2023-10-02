#! /usr/bin/env python3
"""A benchmark to measure the time it takes to load a binary with a given number of functions."""
import timeit
import tempfile
import subprocess
from pathlib import Path
from sqlelf import sql, elf
import time


def create_executable_file(file_name: str, num_functions: int) -> str:
    """Create an ELF executable file with a given number of functions"""
    functions = ""
    for i in range(num_functions):
        functions += f"""void function_{i}() {{ printf("Hello World {i}"); }}\n"""
    content = f"""
    #include <stdio.h>
    {functions}
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


for exponent in range(1, 6):
    num_functions = 10**exponent
    print(f"Number of functions: {num_functions}")
    # create the executable
    with tempfile.NamedTemporaryFile(mode="w") as file:
        file_name = file.name
        binary_file = create_executable_file(file_name, num_functions)
        print(
            "readelf benchmark: {}".format(
                timeit.timeit(
                    lambda: readelf_benchmark(binary_file, num_functions), number=1
                )
            )
        )
        print(
            "sqlelf benchmark: {}".format(
                timeit.timeit(
                    lambda: sqlelf_benchmark(binary_file, num_functions), number=1
                )
            )
        )
