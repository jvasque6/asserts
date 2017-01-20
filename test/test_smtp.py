# -*- coding: utf-8 -*-

"""Modulo para pruebas de SSL.

Este modulo contiene las funciones necesarias para probar si el modulo de
SSL se encuentra adecuadamente implementado.
"""

# standard imports
from __future__ import print_function
import subprocess

# 3rd party imports
import pytest

# local imports
from fluidasserts.service import smtp

# Constants
CONTAINER_IP = '172.30.216.100'


#
# Fixtures
#


@pytest.fixture(scope='module')
def weak_smtp():
    """Configura perfil de SMTP vulnerable."""
    print('Running SMTP vulnerable playbook')
    subprocess.call('ansible-playbook test/provision/postfix.yml \
            --tags=basic,weak', shell=True)


@pytest.fixture(scope='module')
def hard_smtp():
    """Configura perfil de SMTP endurecido."""
    print('Running SMTP hardened playbook')
    subprocess.call('ansible-playbook test/provision/postfix.yml \
            --tags=hard', shell=True)


#
# Open tests
#


@pytest.mark.usefixtures('container', 'weak_smtp')
def test_has_vrfy_open():
    """Funcion VRFY habilitada?"""
    assert smtp.has_vrfy(CONTAINER_IP)

#
# Closing tests
#


@pytest.mark.usefixtures('container', 'hard_smtp')
def test_has_vrfy_close():
    """Funcion VRFY habilitada?"""
    assert not smtp.has_vrfy(CONTAINER_IP)


# Pendente implementar resto de metodos
