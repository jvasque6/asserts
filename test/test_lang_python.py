# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.code.python."""

# standard imports
import io
import sys

# 3rd party imports
# None

# local imports
from fluidasserts.lang import python

# Constants

CODE_DIR = 'test/static/lang/python/'
SECURE_CODE = CODE_DIR + 'exceptions_close.py'
INSECURE_CODE = CODE_DIR + 'exceptions_open.py'
NON_EXISTANT_CODE = CODE_DIR + 'not_exists.py'
LINES_FORMAT = 'lines: '


#
# Open tests
#

def test_has_generic_exceptions_open():
    """Code uses generic exceptions."""
    assert python.has_generic_exceptions(INSECURE_CODE)


def test_has_generic_exceptions_in_dir_open():
    """Code uses generic exceptions."""
    assert python.has_generic_exceptions(CODE_DIR)


def test_swallows_exceptions_open():
    """Code swallows exceptions."""
    capt_out = io.StringIO()
    temp_stdout = sys.stdout
    sys.stdout = capt_out
    expected = LINES_FORMAT + '13, 17, 21'
    assert python.swallows_exceptions(INSECURE_CODE)
    sys.stdout = temp_stdout
    assert expected in capt_out.getvalue()


def test_swallows_exceptions_in_dir_open():
    """Search switch without default clause."""
    assert python.swallows_exceptions(CODE_DIR)


#
# Closing tests
#


def test_has_generic_exceptions_close():
    """Code uses generic exceptions."""
    assert not python.has_generic_exceptions(SECURE_CODE)
    assert not python.has_generic_exceptions(NON_EXISTANT_CODE)


def test_swallows_exceptions_close():
    """Code swallows exceptions."""
    assert not python.swallows_exceptions(SECURE_CODE)
    assert not python.swallows_exceptions(NON_EXISTANT_CODE)
