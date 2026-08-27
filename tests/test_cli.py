import subprocess
import sys
from io import StringIO

import pytest

from sqlelf import cli
from tests.binaries import ELF_FIXTURE


def test_cli_bad_arguments() -> None:
    with pytest.raises(SystemExit):
        cli.start(["--does-not-exist"])


def test_cli_no_arguments() -> None:
    with pytest.raises(SystemExit):
        cli.start([])


def test_cli_single_file_arguments() -> None:
    stdin = StringIO("")
    cli.start([ELF_FIXTURE], stdin)


def test_cli_single_non_existent_file_arguments() -> None:
    with pytest.raises(SystemExit):
        cli.start(["does_not_exist"])


def test_cli_prompt_single_file_arguments() -> None:
    stdin = StringIO(".exit 56\n")
    with pytest.raises(SystemExit) as err:
        cli.start([ELF_FIXTURE], stdin)
    assert err.value.code == 56


def test_cli_frees_lief_objects_on_exit() -> None:
    """A finished run must leave no lief object alive at interpreter shutdown,
    which it checks by running the CLI in a subprocess and asserting that
    nanobind, the binding layer lief is built with, reports no leak."""
    result = subprocess.run(
        [sys.executable, "-m", "sqlelf", "--sql", "SELECT 1", ELF_FIXTURE],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "nanobind: leaked" not in result.stderr
