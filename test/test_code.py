# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.code.code."""

# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts.code import code
import fluidasserts.utils.decorators

# Constants
fluidasserts.utils.decorators.UNITTEST = True
SECURE_CODE = 'test/static/code/c/secure.c'
INSECURE_CODE = 'test/static/code/c/insecure.c'


#
# Open tests
#


def test_has_text_open():
    """Test code has text."""
    assert code.has_text(INSECURE_CODE, 'strcpy')


def test_has_not_text_open():
    """Test code has not text."""
    assert code.has_not_text(INSECURE_CODE, 'strncpy')


def test_file_exists_open():
    """Check if a given file exists."""
    assert code.file_exists(INSECURE_CODE)
#
# Closing tests
#


def test_has_text_close():
    """Test code has text."""
    assert not code.has_text(SECURE_CODE, 'strcpy')


def test_has_not_text_close():
    """Test code has not text."""
    assert not code.has_not_text(SECURE_CODE, 'strncpy')


def test_file_exists_close():
    """Check if a given file exists."""
    assert not code.file_exists('notexistingfile.code')
