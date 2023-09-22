from sqlelf import cli
import pytest
from io import StringIO


def test_cli_bad_arguments() -> None:
    with pytest.raises(SystemExit):
        cli.start(["--does-not-exist"])


def test_cli_no_arguments() -> None:
    with pytest.raises(SystemExit):
        cli.start([])


def test_cli_single_file_arguments() -> None:
    stdin = StringIO("")
    cli.start(["/bin/ls"], stdin)


def test_cli_single_non_existent_file_arguments() -> None:
    with pytest.raises(SystemExit) as err:
        cli.start(["does_not_exist"])


def test_cli_prompt_single_file_arguments() -> None:
    stdin = StringIO(".exit 56\n")
    with pytest.raises(SystemExit) as err:
        cli.start(["/bin/ls"], stdin)
    assert err.value.code == 56
