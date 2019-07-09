# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.format.pkcs12."""

# standard imports
# none

# 3rd party imports
# none

# local imports
from fluidasserts.format import jks


# Constants
PWD_DIR = f'test/static/format/jks/open'
PWD_FILE = f'test/static/format/jks/open/1.jks'
NO_PWD_DIR = f'test/static/format/jks/closed'
NO_PWD_FILE = f'test/static/format/jks/closed/1.jks'
NON_EXISTING_DIR = f'test/static/format/jks/does_not_exist/'
NON_EXISTING_FILE = f'test/static/format/jks/does_not_exist.jks'

#
# Open tests
#


def has_no_password_protection_open():
    """Test if jks file is not password protected."""
    assert jks.has_no_password_protection(NO_PWD_DIR)
    assert jks.has_no_password_protection(NO_PWD_FILE)


#
# Close tests
#


def has_no_password_protection_close():
    """Test if jks file is password protected."""
    assert not jks.has_no_password_protection(PWD_DIR)
    assert not jks.has_no_password_protection(PWD_FILE)
    assert not jks.has_no_password_protection(NON_EXISTING_FILE)


#
# Unknown tests
#


def has_no_password_protection_unknown():
    """Test if jks file does not exist."""
    assert not jks.has_no_password_protection(NON_EXISTING_DIR)
    assert not jks.has_no_password_protection(NON_EXISTING_FILE)
