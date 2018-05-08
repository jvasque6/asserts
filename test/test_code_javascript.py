# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.code.javascript."""

# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts.code import javascript
import fluidasserts.utils.decorators

# Constants
fluidasserts.utils.decorators.UNITTEST = True
CODE_DIR = 'test/static/code/javascript/'
SECURE_CODE = CODE_DIR + 'ConsoleLogClose.js'
INSECURE_CODE = CODE_DIR + 'ConsoleLogOpen.js'


#
# Open tests
#

def test_uses_console_log_open():
    """Search console.log calls."""
    assert javascript.uses_console_log(INSECURE_CODE)


def test_uses_console_log_in_dir_open():
    """Search console.log calls."""
    assert javascript.uses_console_log(CODE_DIR)


def test_uses_localstorage_open():
    """Search localStorage calls."""
    assert javascript.uses_localstorage(INSECURE_CODE)


def test_uses_localstorage_in_dir_open():
    """Search localStorage calls."""
    assert javascript.uses_localstorage(CODE_DIR)


def test_has_insecure_randoms_open():
    """Search Math.random() calls."""
    assert javascript.has_insecure_randoms(INSECURE_CODE)


def test_has_insecure_randoms_in_dir_open():
    """Search Math.random() calls."""
    assert javascript.has_insecure_randoms(CODE_DIR)


def test_swallows_exceptions_open():
    """Search empty catches."""
    assert javascript.swallows_exceptions(INSECURE_CODE)


def test_swallows_exceptions_in_dir_open():
    """Search empty catches."""
    assert javascript.swallows_exceptions(CODE_DIR)


def test_has_switch_without_default_open():
    """Search switches without default clause."""
    assert javascript.has_switch_without_default(INSECURE_CODE)


def test_has_switch_without_default_in_dir_open():
    """Search switches without default clause."""
    assert javascript.has_switch_without_default(CODE_DIR)


def test_has_if_without_else_open():
    """Search conditionals without an else option."""
    assert javascript.has_if_without_else(INSECURE_CODE)


def test_has_if_without_else_in_dir_open():
    """Search conditionals without an else option."""
    assert javascript.has_if_without_else(CODE_DIR)

#
# Closing tests
#


def test_uses_console_log_close():
    """Search console.log calls."""
    assert not javascript.uses_console_log(SECURE_CODE)


def test_uses_localstorage_close():
    """Search localStorage calls."""
    assert not javascript.uses_localstorage(SECURE_CODE)


def test_has_insecure_randoms_close():
    """Search Math.random() calls."""
    assert not javascript.has_insecure_randoms(SECURE_CODE)


def test_swallows_exceptions_close():
    """Search empty catches."""
    assert not javascript.swallows_exceptions(SECURE_CODE)


def test_has_switch_without_default_close():
    """Search switches without default clause."""
    assert not javascript.has_switch_without_default(SECURE_CODE)


def test_has_if_without_else_close():
    """Search conditionals without an else option."""
    assert not javascript.has_if_without_else(SECURE_CODE)
