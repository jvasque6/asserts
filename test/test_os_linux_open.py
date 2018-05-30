# -*- coding: utf-8 -*-

"""Modulo para pruebas de OS.

Este modulo contiene las funciones necesarias para probar si el modulo de
OS se encuentra adecuadamente implementado.
"""

# standard imports
from __future__ import print_function

# 3rd party imports
import pytest

# local imports
from fluidasserts.syst import linux
import fluidasserts.utils.decorators


# Constants
fluidasserts.utils.decorators.UNITTEST = True
ADMIN_USER = 'root'
ADMIN_PASS = 'Puef8poh2tei9AeB'
NONPRIV_USER = 'nonpriv'
NONPRIV_PASS = 'ahgh7xee9eewaeGh'
OS_PORT = 22


#
# Open tests
#

@pytest.mark.parametrize('run_mock',
                         [('os:weak', {'22/tcp': OS_PORT})],
                         indirect=True)
def test_min_priv_enabled_open(run_mock):
    """Secure umask?."""
    assert linux.is_min_priv_disabled(run_mock, NONPRIV_USER, NONPRIV_PASS)


def test_os_sudo_enabled_open(run_mock):
    """Sudo enabled?."""
    assert linux.is_sudo_disabled(run_mock, NONPRIV_USER, NONPRIV_PASS)


def test_compilers_installed_open(run_mock):
    """Compiler installed?."""
    assert linux.are_compilers_installed(run_mock, NONPRIV_USER, NONPRIV_PASS)


def test_antimalware_installed_open(run_mock):
    """Antimalware installed?."""
    assert linux.is_antimalware_not_installed(run_mock, NONPRIV_USER,
                                              NONPRIV_PASS)


def test_remote_admin_enabled_open(run_mock):
    """Remote admin enabled?."""
    assert linux.is_remote_admin_enabled(run_mock, NONPRIV_USER, NONPRIV_PASS)
