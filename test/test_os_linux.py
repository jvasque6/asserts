# -*- coding: utf-8 -*-

"""Modulo para pruebas de OS.

Este modulo contiene las funciones necesarias para probar si el modulo de
OS se encuentra adecuadamente implementado.
"""

# standard imports
from __future__ import print_function
import subprocess

# 3rd party imports
import pytest

# local imports
from fluidasserts.system import linux_generic


# Constants
CONTAINER_IP = '172.30.216.100'
CONTAINER_USER = 'root'
CONTAINER_PASS = 'doesnotexist'
CONTAINER_CONFIG = '/usr/src/asserts/build/config.facont'


#
# Fixtures
#

@pytest.fixture(scope='module')
def weak_os():
    """Configura perfil de OS vulnerable."""
    print('Running OS vulnerable playbook')
    subprocess.call('ansible-playbook test/provision/os.yml \
            --tags weak', shell=True)


@pytest.fixture(scope='module')
def hard_os():
    """Configura perfil de OS endurecido."""
    print('Running OS hardened playbook')
    subprocess.call('ansible-playbook test/provision/os.yml \
            --tags hard', shell=True)


#
# Open tests
#

@pytest.mark.usefixtures('container', 'weak_os')
def test_min_priv_enabled_open():
    """Secure umask?"""
    assert linux_generic.is_os_min_priv_disabled(CONTAINER_IP,
                                                 CONTAINER_USER,
                                                 CONTAINER_PASS,
                                                 CONTAINER_CONFIG)


# @pytest.mark.usefixtures('container', 'weak_os')
# def test_os_sudo_enabled_open():
#    """sudo enabled?"""
#    assert linux_generic.is_os_sudo_disabled(CONTAINER_IP,
#                                      	      CONTAINER_USER,
#                                             CONTAINER_PASS,
#                                             CONTAINER_CONFIG)


@pytest.mark.usefixtures('container', 'weak_os')
def test_compilers_installed_open():
    """Compilers installed?"""
    assert linux_generic.is_os_compilers_installed(CONTAINER_IP,
                                                   CONTAINER_USER,
                                                   CONTAINER_PASS,
                                                   CONTAINER_CONFIG)


@pytest.mark.usefixtures('container', 'weak_os')
def test_antimalware_installed_open():
    """Antimalware installed?"""
    assert linux_generic.is_os_antimalware_not_installed(CONTAINER_IP,
                                                         CONTAINER_USER,
                                                         CONTAINER_PASS,
                                                         CONTAINER_CONFIG)


@pytest.mark.usefixtures('container', 'weak_os')
def test_remote_admin_enabled_open():
    """Remote admin enabled?"""
    assert linux_generic.is_os_remote_admin_enabled(CONTAINER_IP,
                                                    CONTAINER_USER,
                                                    CONTAINER_PASS,
                                                    CONTAINER_CONFIG)


# @pytest.mark.usefixtures('container', 'weak_os')
# def test_syncookies_enabled_open():
#    """SYN Cookies enabled?"""
#    assert linux_generic.is_os_syncookies_disabled(CONTAINER_IP,
#                                                   CONTAINER_USER,
#                                                   CONTAINER_PASS,
#                                                   CONTAINER_CONFIG)

#
# Closing tests
#


# @pytest.mark.usefixtures('container', 'hard_os')
# def test_os_min_priv_enabled_close():
#    """Secure umask?"""
#    assert not linux_generic.is_os_min_priv_disabled(CONTAINER_IP,
#                                                     CONTAINER_USER,
#                                                     CONTAINER_PASS,
#                                                     CONTAINER_CONFIG)


@pytest.mark.usefixtures('container', 'hard_os')
def test_sudo_enabled_close():
    """sudo enabled?"""
    assert not linux_generic.is_os_sudo_disabled(CONTAINER_IP,
                                                 CONTAINER_USER,
                                                 CONTAINER_PASS,
                                                 CONTAINER_CONFIG)


@pytest.mark.usefixtures('container', 'hard_os')
def test_compilers_installed_close():
    """Compilers installed?"""
    assert not linux_generic.is_os_compilers_installed(CONTAINER_IP,
                                                       CONTAINER_USER,
                                                       CONTAINER_PASS,
                                                       CONTAINER_CONFIG)


@pytest.mark.usefixtures('container', 'hard_os')
def test_antimalware_installed_close():
    """Antimalware installed?"""
    assert not linux_generic.is_os_antimalware_not_installed(CONTAINER_IP,
                                                             CONTAINER_USER,
                                                             CONTAINER_PASS,
                                                             CONTAINER_CONFIG)


@pytest.mark.usefixtures('container', 'hard_os')
def test_remote_admin_enabled_close():
    """Remote admin enabled?"""
    assert not linux_generic.is_os_remote_admin_enabled(CONTAINER_IP,
                                                        CONTAINER_USER,
                                                        CONTAINER_PASS,
                                                        CONTAINER_CONFIG)


@pytest.mark.usefixtures('container', 'hard_os')
def test_syncookies_enabled_close():
    """SYN Cookies enabled?"""
    assert not linux_generic.is_os_syncookies_disabled(CONTAINER_IP,
                                                       CONTAINER_USER,
                                                       CONTAINER_PASS,
                                                       CONTAINER_CONFIG)


# Pendente implementar resto de metodos
