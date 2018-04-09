# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.code.rpgle."""

# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts.code import rpgle
import fluidasserts.utils.decorators

# Constants
fluidasserts.utils.decorators.UNITTEST = True
CODE_DIR = 'test/static/code/rpgle/'
SECURE_CODE = CODE_DIR + 'dos_close.rpg'
INSECURE_CODE = CODE_DIR + 'dos_open.rpg'


#
# Open tests
#


def test_has_dos_dow_sqlcod_open():
    """Code has DoS for using DoW SQLCOD = 0."""
    assert rpgle.has_dos_dow_sqlcod(INSECURE_CODE)


def test_has_dos_dow_sqlcod_in_dir_open():
    """Code has DoS for using DoW SQLCOD = 0."""
    assert rpgle.has_dos_dow_sqlcod(CODE_DIR)


def test_has_unitialized_open():
    """Code has unitialized variables."""
    assert rpgle.has_unitialized_vars(INSECURE_CODE)


def test_has_unitialized_in_dir_open():
    """Code has unitialized variables."""
    assert rpgle.has_unitialized_vars(CODE_DIR)


#
# Closing tests
#


def test_has_dos_dow_sqlcod_close():
    """Code has DoS for using DoW SQLCOD = 0."""
    assert not rpgle.has_dos_dow_sqlcod(SECURE_CODE)


def test_has_unitialized_close():
    """Code has unitialized variables."""
    assert not rpgle.has_unitialized_vars(SECURE_CODE)