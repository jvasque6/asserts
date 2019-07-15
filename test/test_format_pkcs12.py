# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.format.pkcs12."""

# standard imports
# none

# 3rd party imports
# none

# local imports
from fluidasserts.format import pkcs12


# Constants
NO_PWD_FILE = 'test/static/format/pkcs12/no_pwd.p12'
NON_EXISTING_FILE = 'test/static/format/pkcs12/does_not_exist.p12'
PWD_FILE = 'test/static/format/pkcs12/pwd.p12'

#
# Open tests
#


def has_no_password_protection_open():
    """p12 file is not password protected."""
    assert pkcs12.has_no_password_protection(NO_PWD_FILE)


#
# Close tests
#


def has_no_password_protection_close():
    """p12 file is password protected or file does not exist."""
    assert not pkcs12.has_no_password_protection(PWD_FILE)
    assert not pkcs12.has_no_password_protection(NON_EXISTING_FILE)
