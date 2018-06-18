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


def test_cli_error():
    """Run CLI."""
    testargs = ["asserts"]
    with patch.object(sys, 'argv', testargs):
       assert cli.main()
