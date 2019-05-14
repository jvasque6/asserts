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
ASSERTS_EXPLOIT = 'test/static/example/test.py'


#
# Open tests
#


def test_cli():
    """Run CLI."""
    os.environ['FA_STRICT'] = 'false'
    testargs = ["asserts", ASSERTS_EXPLOIT]
    with patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            assert not cli.main()


def test_cli_strict():
    """Run CLI in strict mode."""
    os.environ['FA_STRICT'] = 'true'
    testargs = ["asserts", ASSERTS_EXPLOIT]
    with patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
                assert cli.main()


def test_cli_strict_bad():
    """Run CLI with a bad FA_STRICT value."""
    os.environ['FA_STRICT'] = 'badvalue'
    testargs = ["asserts", ASSERTS_EXPLOIT]
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
    testargs = ["asserts", "-q", ASSERTS_EXPLOIT]
    with patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            assert not cli.main()


def test_cli_color():
    """Run CLI in without colors."""
    os.environ['FA_STRICT'] = 'false'
    testargs = ["asserts", "-n", ASSERTS_EXPLOIT]
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
    testargs = ["asserts", "-cou", ASSERTS_EXPLOIT]
    with patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            assert not cli.main()
