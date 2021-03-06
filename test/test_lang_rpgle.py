# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.code.rpgle."""

# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts.lang import rpgle


# Constants

CODE_DIR = 'test/static/lang/rpgle/'
SECURE_CODE = CODE_DIR + 'dos_close.rpg'
INSECURE_CODE = CODE_DIR + 'dos_open.rpg'
NON_EXISTANT_CODE = CODE_DIR + 'not_exists.rpg'


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


def test_has_generic_exceptions_open():
    """Code has empty on-error."""
    assert rpgle.has_generic_exceptions(INSECURE_CODE)


def test_has_generic_exceptions_in_dir_open():
    """Code has empty on-error."""
    assert rpgle.has_generic_exceptions(CODE_DIR)


def test_swallows_exceptions_open():
    """Code swallows exceptions."""
    assert rpgle.swallows_exceptions(INSECURE_CODE)


def test_swallows_exceptions_in_dir_open():
    """Code swallows exceptions."""
    assert rpgle.swallows_exceptions(CODE_DIR)

#
# Closing tests
#


def test_has_dos_dow_sqlcod_close():
    """Code has DoS for using DoW SQLCOD = 0."""
    assert not rpgle.has_dos_dow_sqlcod(SECURE_CODE)
    assert not rpgle.has_dos_dow_sqlcod(CODE_DIR, exclude=['test'])
    assert not rpgle.has_dos_dow_sqlcod(NON_EXISTANT_CODE)


def test_has_unitialized_close():
    """Code has unitialized variables."""
    assert not rpgle.has_unitialized_vars(SECURE_CODE)
    assert not rpgle.has_unitialized_vars(CODE_DIR, exclude=['test'])
    assert not rpgle.has_unitialized_vars(NON_EXISTANT_CODE)


def test_has_generic_exceptions_close():
    """Code has empty on-error."""
    assert not rpgle.has_generic_exceptions(SECURE_CODE)
    assert not rpgle.has_generic_exceptions(CODE_DIR, exclude=['test'])
    assert not rpgle.has_generic_exceptions(NON_EXISTANT_CODE)


def test_swallows_exceptions_close():
    """Code swallows exceptions."""
    assert not rpgle.swallows_exceptions(SECURE_CODE)
    assert not rpgle.swallows_exceptions(CODE_DIR, exclude=['test'])
    assert not rpgle.swallows_exceptions(NON_EXISTANT_CODE)
