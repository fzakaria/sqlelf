"""This file tests the examples in the README.md file"""

import pytest

from sqlelf import elf, sql


@pytest.mark.slow
def test_symbol_resolutions() -> None:
    # TODO(fzakaria): Make sure this binary
    # is always present in the CI environment.
    sql_engine = sql.make_sql_engine(
        ["/usr/bin/ruby"], recursive=True, cache_flags=elf.CacheFlag.SYMBOLS
    )
    result = sql_engine.execute(
        """
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
                       """
    )
    rows = list(result)
    assert len(rows) == 25
