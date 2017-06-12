# -*- coding: utf-8 -*-

"""Modulo para pruebas de SMB.

Este modulo contiene las funciones necesarias para probar si el modulo de
SMB se encuentra adecuadamente implementado.
"""

# standard imports
from __future__ import print_function
import subprocess

# 3rd party imports
import pytest

# local imports
from fluidasserts.service import smb

# Constants
CONTAINER_IP = '172.30.216.100'

#
# Fixtures
#


@pytest.fixture(scope='module')
def weak_smb():
    """Configura perfil de SMB vulnerable."""
    print('Running SMB vulnerable playbook')
    subprocess.call('ansible-playbook test/provision/samba.yml \
            --tags=basic,weak', shell=True)


@pytest.fixture(scope='module')
def hard_smb():
    """Configura perfil de SMB endurecido."""
    print('Running SMB hardened playbook')
    subprocess.call('ansible-playbook test/provision/samba.yml \
            --tags=basic,hard', shell=True)


#
# Open tests
#


@pytest.mark.usefixtures('container', 'weak_smb')
def test_is_anonymous_enabled_open():
    """Conexion anonima habilitada?"""
    assert smb.is_anonymous_enabled(CONTAINER_IP)


#
# Closing tests
#


@pytest.mark.usefixtures('container', 'hard_smb')
def test_is_anonymous_enabled_close():
    """Conexion anonima habilitada?"""
    assert not smb.is_anonymous_enabled(CONTAINER_IP)

# Pendente implementar resto de metodos
