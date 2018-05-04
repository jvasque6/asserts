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
SECURE_EMPTY_CATCH = CODE_DIR + 'GenericExceptionsOpen.java'
INSECURE_EMPTY_CATCH = CODE_DIR + 'EmptyCatchOpen.java'
INSECURE_SWITCH = CODE_DIR + 'SwitchDefaultOpen.java'
SECURE_SWITCH = CODE_DIR + 'SwitchDefaultClose.java'

#
# Open tests
#


def test_has_generic_exceptions_open():
    """Code uses generic exceptions."""
    assert java.has_generic_exceptions(INSECURE_CODE)


def test_has_generic_exceptions_in_dir_open():
    """Code uses generic exceptions."""
    assert java.has_generic_exceptions(CODE_DIR)


def test_uses_print_stack_trace_open():
    """Search printStackTrace calls."""
    assert java.uses_print_stack_trace(INSECURE_CODE)


def test_uses_print_stack_trace_in_dir_open():
    """Search printStackTrace calls."""
    assert java.uses_print_stack_trace(CODE_DIR)


def test_swallows_exceptions_open():
    """Search empty catches."""
    assert java.swallows_exceptions(INSECURE_EMPTY_CATCH)


def test_has_empty_catches_in_dir_open():
    """Search empty catches."""
    assert java.swallows_exceptions(CODE_DIR)


def test_has_switch_without_default_open():
    """Search switch without default clause."""
    assert java.has_switch_without_default(INSECURE_SWITCH)


def test_has_switch_without_default_in_dir_open():
    """Search switch without default clause."""
    assert java.has_switch_without_default(CODE_DIR)


#
# Closing tests
#


def test_has_generic_exceptions_close():
    """Code uses generic exceptions."""
    assert not java.has_generic_exceptions(SECURE_CODE)


def test_uses_print_stack_trace_close():
    """Search printStackTrace calls."""
    assert not java.uses_print_stack_trace(SECURE_CODE)


def test_has_empty_catches_close():
    """Search empty catches."""
    assert not java.swallows_exceptions(SECURE_EMPTY_CATCH)


def test_has_switch_without_default_close():
    """Search switch without default clause."""
    assert not java.has_switch_without_default(SECURE_SWITCH)
