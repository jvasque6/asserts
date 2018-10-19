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
                         [('mysql:weak', {'22/tcp': OS_PORT})],
                         indirect=True)
def test_history_enabled_open(run_mock):
    """MySQL history files non empty?."""
    assert mysql_os.history_enabled(run_mock, ADMIN_USER, ADMIN_PASS)


def test_pwd_on_env_open(run_mock):
    """MYSQL_PWD on env?."""
    assert mysql_os.pwd_on_env(run_mock, ADMIN_USER, ADMIN_PASS)
