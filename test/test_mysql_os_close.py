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
                         [('mysql_os:hard', {'22/tcp': OS_PORT})],
                         indirect=True)
def test_high_privileged_close(run_mock):
    """Daemon running with high privileges?."""
    assert not mysql_os.daemon_high_privileged(run_mock, ADMIN_USER,
                                               ADMIN_PASS)
    assert not mysql_os.daemon_high_privileged(NON_EXISTANT, ADMIN_USER,
                                               ADMIN_PASS)


def test_history_enabled_close(run_mock):
    """MySQL history files non empty?."""
    assert not mysql_os.history_enabled(run_mock, ADMIN_USER,
                                        ADMIN_PASS)
    assert not mysql_os.history_enabled(NON_EXISTANT, ADMIN_USER,
                                        ADMIN_PASS)


def test_pwd_on_env_close(run_mock):
    """MYSQL_PWD on env?."""
    assert not mysql_os.pwd_on_env(run_mock, ADMIN_USER, ADMIN_PASS)
    assert not mysql_os.pwd_on_env(NON_EXISTANT, ADMIN_USER, ADMIN_PASS)


def test_has_insecure_shell_close(run_mock):
    """mysql has interactive shell?."""
    assert not mysql_os.has_insecure_shell(run_mock, ADMIN_USER, ADMIN_PASS)
    assert not mysql_os.has_insecure_shell(NON_EXISTANT, ADMIN_USER,
                                           ADMIN_PASS)
