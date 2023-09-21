from sqlelf import sql
import lief


def test_simple_select_header():
    engine = sql.make_sql_engine([lief.parse("/bin/ls")])
    result = list(engine.execute("SELECT * FROM elf_headers LIMIT 1"))
    assert len(result) == 1
    assert "path" in result[0]
    assert "type" in result[0]
    assert "version" in result[0]
    assert "machine" in result[0]
    assert "entry" in result[0]
