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
from fluidasserts.system import linux_generic


# Constants
CONTAINER_IP = '172.30.216.101'
ADMIN_USER = 'root'
ADMIN_PASS = 'Puef8poh2tei9AeB'
NONPRIV_USER = 'nonpriv'
NONPRIV_PASS = 'ahgh7xee9eewaeGh'
OS_PORT = 22


#
# Open tests
#


# pylint: disable=unused-argument
# def test_min_priv_enabled_close(run_mock):
    # """Secure umask?"""
    # assert not linux_generic.is_os_min_priv_disabled(CONTAINER_IP,
                                                     # NONPRIV_USER,
                                                     # NONPRIV_PASS)

@pytest.mark.parametrize('run_mock',
                         [('os:hard', {'22/tcp': OS_PORT})],
                         indirect=True)
# pylint: disable=unused-argument
def test_os_sudo_enabled_close(run_mock):
    """sudo enabled?"""
    assert not linux_generic.is_os_sudo_disabled(CONTAINER_IP,
                                                 NONPRIV_USER,
                                                 NONPRIV_PASS)


# pylint: disable=unused-argument
def test_compilers_installed_close(run_mock):
    """Compilers installed?"""
    assert not linux_generic.is_os_compilers_installed(CONTAINER_IP,
                                                       NONPRIV_USER,
                                                       NONPRIV_PASS)


# pylint: disable=unused-argument
def test_antimalware_installed_close(run_mock):
    """Antimalware installed?"""
    assert not linux_generic.is_os_antimalware_not_installed(CONTAINER_IP,
                                                             NONPRIV_USER,
                                                             NONPRIV_PASS)


# pylint: disable=unused-argument
def test_remote_admin_enabled_close(run_mock):
    """Remote admin enabled?"""
    assert not linux_generic.is_os_remote_admin_enabled(CONTAINER_IP,
                                                        NONPRIV_USER,
                                                        NONPRIV_PASS)


def test_syncookies_enabled_close():
    """SYN Cookies enabled?"""
    assert not linux_generic.is_os_syncookies_disabled(CONTAINER_IP,
                                                       NONPRIV_USER,
                                                       NONPRIV_PASS)
