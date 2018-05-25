# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.code.webconfig."""

# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts.lang import webconfig
import fluidasserts.utils.decorators

# Constants
fluidasserts.utils.decorators.UNITTEST = True
CODE_DIR = 'test/static/lang/webconfig/'
SECURE_CODE = CODE_DIR + 'webNotVuln.config'
INSECURE_CODE = CODE_DIR + 'webVuln.config'
NON_EXISTANT_CODE = CODE_DIR + 'notExists.config'

#
# Open tests
#


def test_is_header_x_powered_by_present_open():
    """Code uses generic exceptions."""
    assert webconfig.is_header_x_powered_by_present(INSECURE_CODE)


def test_is_header_x_powered_by_present_in_dir_open():
    """Code uses generic exceptions."""
    assert webconfig.is_header_x_powered_by_present(CODE_DIR)


#
# Closing tests
#


def test_is_header_x_powered_by_present_close():
    """Code uses generic exceptions."""
    assert not webconfig.is_header_x_powered_by_present(SECURE_CODE)
    assert not webconfig.is_header_x_powered_by_present(NON_EXISTANT_CODE)
