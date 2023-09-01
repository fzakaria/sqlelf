from sqlelf import cli
import pytest
from io import StringIO

def test_cli_bad_arguments():
    with pytest.raises(SystemExit):
        cli.start(["--does-not-exist"])

def test_cli_no_arguments():
    with pytest.raises(SystemExit):
        cli.start([])

def test_cli_single_file_arguments():
    stdin = StringIO("")
    cli.start(["/bin/ls"], stdin)

def test_cli_prompt_single_file_arguments():
    stdin = StringIO(".exit 56\n")
    with pytest.raises(SystemExit) as err:
        cli.start(["/bin/ls"], stdin)
    assert err.value.code == 56