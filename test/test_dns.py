# -*- coding: utf-8 -*-

"""Modulo para pruebas de DNS.

Este modulo contiene las funciones necesarias para probar si el modulo de
DNS se encuentra adecuadamente implementado.
"""

# standard imports
import subprocess

# 3rd party imports
import pytest

# local imports
from fluidasserts import dns

# Constants
CONTAINER_IP = '172.30.216.100'
TEST_ZONE = 'fluid.la'

#
# Fixtures
#


# pylint: disable=unused-argument
@pytest.fixture(scope='module')
def weak_dns(request):
    """Configura perfil de DNS vulnerable."""
    print('Running DNS vulnerable playbook')
    subprocess.call('ansible-playbook test/provision/dns.yml \
            --tags basic,weak', shell=True)


# pylint: disable=unused-argument
@pytest.fixture(scope='module')
def hard_dns(request):
    """Configura perfil de DNS endurecido."""
    print('Running DNS hardened playbook')
    subprocess.call('ansible-playbook test/provision/dns.yml \
            --tags basic,hard', shell=True)


#
# Open tests
#


@pytest.mark.usefixtures('container', 'weak_dns')
def test_dns_is_xfr_enabled_open():
    """Transferencia de zonas habilitado en server?"""
    assert dns.is_xfr_enabled(TEST_ZONE, CONTAINER_IP)

#
# Closing tests
#


@pytest.mark.usefixtures('container', 'hard_dns')
def test_dns_is_xfr_enabled_close():
    """Transferencia de zonas habilitado en server?"""
    assert not dns.is_xfr_enabled(TEST_ZONE, CONTAINER_IP)

# Pendente implementar resto de metodos
