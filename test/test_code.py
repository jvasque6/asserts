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
SECURE_CODE = 'test/provision/code/secure.c'
INSECURE_CODE = 'test/provision/code/insecure.c'


#
# Open tests
#


def test_has_text_open():
    """Test code has text."""
    assert code.has_text(INSECURE_CODE, 'strcpy')


def test_has_not_text_open():
    """Test code has not text."""
    assert code.has_not_text(INSECURE_CODE, 'strncpy')
#
# Closing tests
#


def test_has_text_close():
    """Test code has text."""
    assert not code.has_text(SECURE_CODE, 'strcpy')


def test_has_not_text_close():
    """Test code has not text."""
    assert not code.has_not_text(SECURE_CODE, 'strncpy')
