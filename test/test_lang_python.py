# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.code.python."""

# standard imports
# None

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
    assert python.swallows_exceptions(INSECURE_CODE)


def test_swallows_exceptions_in_dir_open():
    """Search switch without default clause."""
    assert python.swallows_exceptions(CODE_DIR)


def test_insecure_functions_open():
    """Search for insecure functions."""
    assert python.uses_insecure_functions(INSECURE_CODE)


def test_insecure_functions_in_dir_open():
    """Search for insecure functions."""
    assert python.uses_insecure_functions(CODE_DIR)

#
# Closing tests
#


def test_has_generic_exceptions_close():
    """Code uses generic exceptions."""
    assert not python.has_generic_exceptions(SECURE_CODE)
    assert not python.has_generic_exceptions(NON_EXISTANT_CODE)
    assert not python.has_generic_exceptions(CODE_DIR, exclude=['test'])


def test_swallows_exceptions_close():
    """Code swallows exceptions."""
    assert not python.swallows_exceptions(SECURE_CODE)
    assert not python.swallows_exceptions(NON_EXISTANT_CODE)
    assert not python.swallows_exceptions(CODE_DIR, exclude=['test'])


def test_insecure_functions_close():
    """Search for insecure functions."""
    assert not python.uses_insecure_functions(SECURE_CODE)
    assert not python.uses_insecure_functions(NON_EXISTANT_CODE)
    assert not python.uses_insecure_functions(CODE_DIR,
                                              exclude=['exceptions_open'])
