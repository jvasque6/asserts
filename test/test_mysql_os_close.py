# -*- coding: utf-8 -*-

"""Test module for mysql_os."""

# standard imports
from __future__ import print_function

# 3rd party imports
import pytest

# local imports
from fluidasserts.syst import mysql_os


# Constants

ADMIN_USER = 'root'
ADMIN_PASS = 'Puef8poh2tei9AeB'
NONPRIV_USER = 'nonpriv'
NONPRIV_PASS = 'ahgh7xee9eewaeGh'
OS_PORT = 22
NON_EXISTANT = '0.0.0.0'


#
# Open tests
#


@pytest.mark.parametrize('run_mock',
                         [('mysql:hard', {'22/tcp': OS_PORT})],
                         indirect=True)
def test_min_priv_enabled_close(run_mock):
    """Secure umask?."""
    assert not mysql_os.daemon_high_privileged(run_mock, NONPRIV_USER,
                                               NONPRIV_PASS)
    assert not mysql_os.daemon_high_privileged(NON_EXISTANT, NONPRIV_USER,
                                               NONPRIV_PASS)
