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

def test_has_console_log_open():
    """Search console.log calls."""
    assert javascript.uses_console_log(INSECURE_CODE)


def test_has_console_log_in_dir_open():
    """Search console.log calls."""
    assert javascript.uses_console_log(CODE_DIR)

#
# Closing tests
#


def test_has_console_log_close():
    """Search console.log calls."""
    assert not javascript.uses_console_log(SECURE_CODE)
