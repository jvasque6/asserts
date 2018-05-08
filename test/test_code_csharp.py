# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.code.java."""

# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts.code import csharp
import fluidasserts.utils.decorators

# Constants
fluidasserts.utils.decorators.UNITTEST = True
CODE_DIR = 'test/static/code/csharp/'
SECURE_CODE = CODE_DIR + 'GenericExceptionsClose.cs'
INSECURE_CODE = CODE_DIR + 'GenericExceptionsOpen.cs'
SECURE_EMPTY_CATCH = CODE_DIR + 'GenericExceptionsOpen.cs'
INSECURE_EMPTY_CATCH = CODE_DIR + 'EmptyCatchOpen.cs'
INSECURE_SWITCH = CODE_DIR + 'SwitchDefaultOpen.cs'
SECURE_SWITCH = CODE_DIR + 'SwitchDefaultClose.cs'
INSECURE_RANDOM = CODE_DIR + 'SwitchDefaultOpen.cs'
SECURE_RANDOM = CODE_DIR + 'SwitchDefaultClose.cs'

#
# Open tests
#


def test_has_generic_exceptions_open():
    """Code uses generic exceptions."""
    assert csharp.has_generic_exceptions(INSECURE_CODE)


def test_has_generic_exceptions_in_dir_open():
    """Code uses generic exceptions."""
    assert csharp.has_generic_exceptions(CODE_DIR)


def test_swallows_exceptions_open():
    """Search empty catches."""
    assert csharp.swallows_exceptions(INSECURE_EMPTY_CATCH)


def test_swallows_exceptions_in_dir_open():
    """Search empty catches."""
    assert csharp.swallows_exceptions(CODE_DIR)


def test_has_switch_without_default_open():
    """Search switch without default clause."""
    assert csharp.has_switch_without_default(INSECURE_SWITCH)


def test_has_switch_without_default_in_dir_open():
    """Search switch without default clause."""
    assert csharp.has_switch_without_default(CODE_DIR)


def test_has_insecure_randoms_open():
    """Search class Random instantiation."""
    assert csharp.has_insecure_randoms(INSECURE_RANDOM)


def test_has_insecure_randoms_in_dir_open():
    """Search class Random instantiation."""
    assert csharp.has_insecure_randoms(CODE_DIR)


def test_has_if_without_else_open():
    """Search conditionals without an else option."""
    assert csharp.has_if_without_else(INSECURE_CODE)


def test_has_if_without_else_in_dir_open():
    """Search conditionals without an else option."""
    assert csharp.has_if_without_else(CODE_DIR)


def test_uses_md5_hash_open():
    """Search MD5.Create() calls."""
    assert csharp.uses_md5_hash(INSECURE_CODE)


def test_uses_md5_hash_in_dir_open():
    """Search MD5.Create() calls."""
    assert csharp.uses_md5_hash(CODE_DIR)


#
# Closing tests
#


def test_has_generic_exceptions_close():
    """Code uses generic exceptions."""
    assert not csharp.has_generic_exceptions(SECURE_CODE)


def test_swallows_exceptions_close():
    """Search empty catches."""
    assert not csharp.swallows_exceptions(SECURE_EMPTY_CATCH)


def test_has_switch_without_default_close():
    """Search switch without default clause."""
    assert not csharp.has_switch_without_default(SECURE_SWITCH)


def test_has_insecure_randoms_close():
    """Search class Random instantiation."""
    assert not csharp.has_insecure_randoms(SECURE_RANDOM)


def test_has_if_without_else_close():
    """Search conditionals without an else option."""
    assert not csharp.has_if_without_else(SECURE_CODE)


def test_uses_md5_hash_close():
    """Search MD5.Create() calls."""
    assert not csharp.uses_md5_hash(SECURE_CODE)
