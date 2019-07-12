# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.sca packages."""

# standard imports
import os
import pytest
import sys
from unittest.mock import patch

# 3rd party imports
# None

# local imports
from fluidasserts.utils import cli

# Constants
EXPLOIT_OPEN = 'test/static/example/test_open.py'
EXPLOIT_CLOSED = 'test/static/example/test_closed.py'
EXPLOIT_UNKNOWN = 'test/static/example/test_unknown.py'
EXPLOIT_WITH_ERRORS = 'test/static/example/test_with_errors.py'
EXPLOIT_BAD_PATH = 'non-existing-exploit'

#
# Open tests
#


def test_cli():
    """Run CLI."""
    os.environ['FA_STRICT'] = 'false'
    testargs = ["asserts", EXPLOIT_OPEN]
    with patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            assert not cli.main()


def test_cli_strict():
    """Run CLI in strict mode."""
    os.environ['FA_STRICT'] = 'true'
    testargs = ["asserts", EXPLOIT_OPEN]
    with patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            assert cli.main()


def test_cli_strict_with_rich_exit_codes():
    """Run CLI in strict mode."""
    os.environ['FA_STRICT'] = 'true'
    testargs = ["asserts", "--enrich-exit-codes", EXPLOIT_OPEN]
    with patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            assert cli.main()


def test_cli_strict_bad():
    """Run CLI with a bad FA_STRICT value."""
    os.environ['FA_STRICT'] = 'badvalue'
    testargs = ["asserts", EXPLOIT_OPEN]
    with patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            assert cli.main()


def test_cli_noargs():
    """Run CLI with no args."""
    os.environ['FA_STRICT'] = 'false'
    testargs = ["asserts"]
    with patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            assert cli.main()


def test_cli_quiet():
    """Run CLI in quiet mode."""
    os.environ['FA_STRICT'] = 'false'
    testargs = ["asserts", "-q", EXPLOIT_OPEN]
    with patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            assert not cli.main()


def test_cli_output():
    """Run CLI output option."""
    log_file = "log.asserts"
    os.environ['FA_STRICT'] = 'false'
    testargs = ["asserts", "-q", "-O", log_file, EXPLOIT_OPEN]
    with patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            cli.main()
            assert os.path.exists(log_file)
            os.unlink(log_file)


def test_cli_color():
    """Run CLI in without colors."""
    os.environ['FA_STRICT'] = 'false'
    testargs = ["asserts", "-n", EXPLOIT_OPEN]
    with patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            assert not cli.main()


def test_cli_http():
    """Run CLI http option."""
    os.environ['FA_STRICT'] = 'false'
    testargs = ["asserts", "-H", 'https://127.0.0.1']
    with patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            assert not cli.main()


def test_cli_ssl():
    """Run CLI ssl option."""
    os.environ['FA_STRICT'] = 'false'
    testargs = ["asserts", "-S", '127.0.0.1']
    with patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            assert not cli.main()


def test_cli_dns():
    """Run CLI dns option."""
    os.environ['FA_STRICT'] = 'false'
    testargs = ["asserts", "-D", '127.0.0.1']
    with patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            assert not cli.main()


def test_cli_lang():
    """Run CLI lang option."""
    os.environ['FA_STRICT'] = 'false'
    testargs = ["asserts", "-L", 'test/static/lang/csharp/']
    with patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            assert not cli.main()


def test_cli_filtered():
    """Run CLI with filtered results."""
    os.environ['FA_STRICT'] = 'false'
    testargs = ["asserts", "-cou", EXPLOIT_OPEN]
    with patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            assert not cli.main()


def test_cli_method_stats():
    """Run CLI with method stats flag."""
    os.environ['FA_STRICT'] = 'false'
    testargs = ["asserts", "-ms", EXPLOIT_OPEN]
    with patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            assert not cli.main()


def test_exec_wrapper_success():
    """Run the exec wrapper and expects it catches the error."""
    with pytest.raises(BaseException):
        # The method should not propagate any exploit errors and handle them
        assert not cli.exec_wrapper(
            cli.get_exploit_content(EXPLOIT_OPEN))


def test_exec_wrapper_failure():
    """Run the exec wrapper and expects it catches the error."""
    with pytest.raises(BaseException):
        # The method should not propagate any exploit errors and handle them
        assert not cli.exec_wrapper(
            cli.get_exploit_content(EXPLOIT_WITH_ERRORS))


def test_exit_codes_strict():
    """Test the exit codes running in strict mode."""
    os.environ['FA_STRICT'] = 'true'
    with patch.object(sys, 'argv', ["asserts"]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_CODES['config-error']
    with patch.object(sys, 'argv', ["asserts", EXPLOIT_OPEN]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_CODES['open']
    with patch.object(sys, 'argv', ["asserts", EXPLOIT_CLOSED]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_CODES['closed']
    with patch.object(sys, 'argv', ["asserts", EXPLOIT_UNKNOWN]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_CODES['unknown']
    with patch.object(sys, 'argv', ["asserts", EXPLOIT_WITH_ERRORS]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_CODES['exploit-error']
    with patch.object(sys, 'argv', ["asserts", EXPLOIT_BAD_PATH]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.EXIT_CODES['exploit-not-found']


def test_exit_codes_non_strict():
    """Test the exit codes running in non strict mode."""
    os.environ['FA_STRICT'] = 'false'
    with patch.object(sys, 'argv', ["asserts"]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0
    with patch.object(sys, 'argv', ["asserts", EXPLOIT_OPEN]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0
    with patch.object(sys, 'argv', ["asserts", EXPLOIT_CLOSED]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0
    with patch.object(sys, 'argv', ["asserts", EXPLOIT_UNKNOWN]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0
    with patch.object(sys, 'argv', ["asserts", EXPLOIT_WITH_ERRORS]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0
    with patch.object(sys, 'argv', ["asserts", EXPLOIT_BAD_PATH]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0


def test_rich_exit_codes_strict():
    """Test the rich exit codes running in strict mode."""
    os.environ['FA_STRICT'] = 'true'
    with patch.object(sys, 'argv', ["asserts", "-eec"]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.RICH_EXIT_CODES['config-error']
    with patch.object(sys, 'argv', ["asserts", "-eec", EXPLOIT_OPEN]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.RICH_EXIT_CODES['open']
    with patch.object(sys, 'argv', ["asserts", "-eec", EXPLOIT_CLOSED]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.RICH_EXIT_CODES['closed']
    with patch.object(sys, 'argv', ["asserts", "-eec", EXPLOIT_UNKNOWN]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.RICH_EXIT_CODES['unknown']
    with patch.object(sys, 'argv', ["asserts", "-eec", EXPLOIT_WITH_ERRORS]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.RICH_EXIT_CODES['exploit-error']
    with patch.object(sys, 'argv', ["asserts", "-eec", EXPLOIT_BAD_PATH]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == cli.RICH_EXIT_CODES['exploit-not-found']


def test_rich_exit_codes_non_strict():
    """Test the rich exit codes running in non strict mode."""
    os.environ['FA_STRICT'] = 'false'
    with patch.object(sys, 'argv', ["asserts", "-eec"]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0
    with patch.object(sys, 'argv', ["asserts", "-eec", EXPLOIT_OPEN]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0
    with patch.object(sys, 'argv', ["asserts", "-eec", EXPLOIT_CLOSED]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0
    with patch.object(sys, 'argv', ["asserts", "-eec", EXPLOIT_UNKNOWN]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0
    with patch.object(sys, 'argv', ["asserts", "-eec", EXPLOIT_WITH_ERRORS]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0
    with patch.object(sys, 'argv', ["asserts", "-eec", EXPLOIT_BAD_PATH]):
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 0
