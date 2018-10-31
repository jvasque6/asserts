# -*- coding: utf-8 -*-

"""Modulo para pruebas de DNS.

Este modulo contiene las funciones necesarias para probar si el modulo de
DNS se encuentra adecuadamente implementado.
"""

# standard imports
from __future__ import print_function

# 3rd party imports
import pytest

# local imports
from fluidasserts.proto import dns


# Constants

TEST_ZONE = 'fluid.la'
WEAK_PORT = 53
HARD_PORT = 53


#
# Open tests
#


@pytest.mark.parametrize('get_mock_ip', ['dns_weak'], indirect=True)
def test_is_xfr_enabled_open(get_mock_ip):
    """Transferencia de zonas habilitado en server?."""
    assert dns.is_xfr_enabled(TEST_ZONE, get_mock_ip)


@pytest.mark.parametrize('get_mock_ip', ['dns_weak'], indirect=True)
def test_has_cache_poison_open(get_mock_ip):
    """Server vulnerable a cache poison?."""
    assert dns.has_cache_poison(TEST_ZONE, get_mock_ip)


@pytest.mark.parametrize('get_mock_ip', ['dns_weak'], indirect=True)
def test_has_cache_snooping_open(get_mock_ip):
    """Server vulnerable a cache snooping?."""
    assert dns.has_cache_snooping(get_mock_ip)


@pytest.mark.parametrize('get_mock_ip', ['dns_weak'], indirect=True)
def test_has_recursion_open(get_mock_ip):
    """Server has recursion enabled?."""
    assert dns.has_recursion(get_mock_ip)


@pytest.mark.parametrize('get_mock_ip', ['dns_weak'], indirect=True)
def test_can_amplify_open(get_mock_ip):
    """Server can perform DNS amplification attacks?."""
    assert dns.can_amplify(get_mock_ip)
