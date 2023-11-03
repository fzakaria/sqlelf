#! /usr/bin/env python3
import os
import pprint
import signal
import sys

from sqlelf import elf, sql


class TimeOutException(Exception):
    pass


def alarm_handler(signum, frame):
    print("ALARM signal received")  # noqa: T201
    raise TimeOutException()


directory = sys.argv[1]

for root, dirs, files in os.walk(directory):
    for file in files:
        try:
            full_filename = os.path.join(root, file)
            print(f"Investigating {full_filename}")  # noqa: T201

            # setup the timeout
            signal.signal(signal.SIGALRM, alarm_handler)
            signal.alarm(10)

            engine = sql.make_sql_engine(
                [full_filename], recursive=True, cache_flags=elf.CacheFlag.SYMBOLS
            )
            # ignore .bss since it is symbols which are declared but have no value
            # i need to understand them more but they tend to show up.
            # let us also exclude the main binary and catch only interposition
            # from shared objects
            results = engine.execute(
                """
                SELECT name, elf_symbols.version, count(*) as symbol_count,
                    GROUP_CONCAT(elf_headers.path, ':') as libraries
                FROM elf_symbols, elf_headers
                WHERE elf_symbols.path = elf_headers.path AND
                      elf_headers.is_pie = 0 AND
                      exported = TRUE AND section != '.bss'
                GROUP BY name, elf_symbols.version
                HAVING count(*) >= 2
                """
            )
            rows = list(results)
            rows = list(
                filter(
                    lambda r: "libc" not in r["libraries"]
                    and "libm" not in r["libraries"],
                    rows,
                )
            )
            if len(rows) > 0:
                print(f"Found {len(rows)} duplicate symbols")  # noqa: T201
                pprint.pprint(rows)  # noqa: T203
        except TimeOutException as ex:
            print(ex)  # noqa: T201
        except Exception as ex:
            print(ex)  # noqa: T201
        finally:
            signal.alarm(0)
