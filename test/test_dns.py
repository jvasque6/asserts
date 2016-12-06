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
from fluidasserts.service import moddns

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
    assert moddns.is_xfr_enabled(TEST_ZONE, CONTAINER_IP)


@pytest.mark.usefixtures('container', 'weak_dns')
def test_dns_is_dynupdates_enabled_open():
    """Actualizacion de zonas habilitado en server?"""
    assert moddns.is_dynupdate_enabled(TEST_ZONE, CONTAINER_IP)


@pytest.mark.usefixtures('container', 'weak_dns')
def test_dns_has_cache_poison_open():
    """Server vulnerable a cache poison?"""
    assert moddns.has_cache_poison(TEST_ZONE, CONTAINER_IP)


@pytest.mark.usefixtures('container', 'weak_dns')
def test_dns_has_cache_snooping_open():
    """Server vulnerable a cache snooping?"""
    assert moddns.has_cache_snooping(CONTAINER_IP)

#
# Closing tests
#


@pytest.mark.usefixtures('container', 'hard_dns')
def test_dns_is_xfr_enabled_close():
    """Transferencia de zonas habilitado en server?"""
    assert not moddns.is_xfr_enabled(TEST_ZONE, CONTAINER_IP)


@pytest.mark.usefixtures('container', 'hard_dns')
def test_dns_is_dynupdates_enabled_close():
    """Actualizacion de zonas habilitado en server?"""
    assert not moddns.is_dynupdate_enabled(TEST_ZONE, CONTAINER_IP)


@pytest.mark.usefixtures('container', 'hard_dns')
def test_dns_has_cache_poison_close():
    """Server vulnerable a cache poison?"""
    assert not moddns.has_cache_poison(TEST_ZONE, CONTAINER_IP)


@pytest.mark.usefixtures('container', 'hard_dns')
def test_dns_has_cache_snooping_close():
    """Server vulnerable a cache snooping?"""
    assert not moddns.has_cache_snooping(CONTAINER_IP)

# Pendente implementar resto de metodos
