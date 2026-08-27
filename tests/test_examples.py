"""This file tests the examples in the README.md file"""

import pytest

from sqlelf import elf, sql
from tests.binaries import can_resolve_libraries

# A binary big enough to pull in a deep enough library graph for the join
# below to find 25 cross-object symbol resolutions.
RUBY = "/usr/bin/ruby"


@pytest.mark.slow
@pytest.mark.skipif(
    not can_resolve_libraries(RUBY),
    reason=f"{RUBY} is not an ELF binary whose libraries can be resolved here",
)
def test_symbol_resolutions() -> None:
    sql_engine = sql.make_sql_engine(
        [RUBY], recursive=True, cache_flags=elf.CacheFlag.SYMBOLS
    )
    result = sql_engine.execute("""
                        SELECT caller.path as 'caller.path',
                            callee.path as 'calee.path',
                            caller.name,
                            caller.demangled_name
                        FROM ELF_SYMBOLS caller
                        INNER JOIN ELF_SYMBOLS callee
                        ON
                        caller.name = callee.name AND
                        caller.path != callee.path AND
                        caller.imported = TRUE AND
                        callee.exported = TRUE
                        LIMIT 25
                       """)
    rows = list(result)
    assert len(rows) == 25
