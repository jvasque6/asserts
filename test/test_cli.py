# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.sca packages."""

# standard imports
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
    testargs = ["asserts", ASSERTS_EXPLOIT]
    with patch.object(sys, 'argv', testargs):
       assert not cli.main()


def test_cli_quiet():
    """Run CLI in quiet mode."""
    testargs = ["asserts", "-q", ASSERTS_EXPLOIT]
    with patch.object(sys, 'argv', testargs):
       assert not cli.main()


def test_cli_color():
    """Run CLI in without colors."""
    testargs = ["asserts", "-c", ASSERTS_EXPLOIT]
    with patch.object(sys, 'argv', testargs):
       assert not cli.main()


def test_cli_http():
    """Run CLI http option."""
    testargs = ["asserts", "-H", 'https://127.0.0.1']
    with patch.object(sys, 'argv', testargs):
       assert not cli.main()


def test_cli_filtered():
    """Run CLI with filtered results."""
    testargs = ["asserts", "-cou", ASSERTS_EXPLOIT]
    with patch.object(sys, 'argv', testargs):
       assert not cli.main()
