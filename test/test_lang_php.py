# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.code.php."""

# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts.lang import php

# Constants

CODE_DIR = 'test/static/lang/php/'
SECURE_CODE = CODE_DIR + 'safe_code.php'
INSECURE_CODE = CODE_DIR + 'vuln_code.php'
NON_EXISTANT_CODE = CODE_DIR + 'not_exists.php'
LINES_FORMAT = 'lines: '


#
# Open tests
#

def test_has_preg_rce_open():
    """Code uses unsafe preg_replace."""
    assert php.has_preg_ce(INSECURE_CODE)


def test_has_preg_rce_in_dir_open():
    """Code uses unsafe preg_replace."""
    assert php.has_preg_ce(CODE_DIR)

#
# Closing tests
#


def test_has_preg_rce_close():
    """Code uses unsafe preg_replace."""
    assert not php.has_preg_ce(SECURE_CODE)
    assert not php.has_preg_ce(NON_EXISTANT_CODE)
    assert not php.has_preg_ce(CODE_DIR, exclude=['test'])
