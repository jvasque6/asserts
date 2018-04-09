# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.code.java."""

# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts.code import java
import fluidasserts.utils.decorators

# Constants
fluidasserts.utils.decorators.UNITTEST = True
CODE_DIR = 'test/static/code/java/'
SECURE_CODE = CODE_DIR + 'GenericExceptionsClose.java'
INSECURE_CODE = CODE_DIR + 'GenericExceptionsOpen.java'


#
# Open tests
#


def test_has_generic_exceptions_open():
    """Code uses generic exceptions."""
    assert java.has_generic_exceptions(INSECURE_CODE)


def test_has_generic_exceptions_in_dir_open():
    """Code uses generic exceptions."""
    assert java.has_generic_exceptions(CODE_DIR)

#
# Closing tests
#


def test_has_generic_exceptions_close():
    """Code uses generic exceptions."""
    assert not java.has_generic_exceptions(SECURE_CODE)
