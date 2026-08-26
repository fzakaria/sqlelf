from tests.test_sql import _binary_is_elf, _default_test_binary


def test_default_test_binary_is_elf() -> None:
    assert _binary_is_elf(_default_test_binary())
