from sqlelf import ldd
import lief

def test_simple_binary():
    binary = lief.parse("/bin/ls")
    result = ldd.libraries(binary)
    print(result)
    assert len(result) > 0