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
from fluidasserts.service import dns

# Constants
CONTAINER_IP = '172.30.216.101'
TEST_ZONE = 'fluid.la'
WEAK_PORT = 53
HARD_PORT = 53

#
# Closing tests
#


@pytest.mark.parametrize('run_mock',
                         [('dns:hard', {'53/tcp': HARD_PORT,
                                        '53/udp': HARD_PORT})],
                         indirect=True)
# pylint: disable=unused-argument
def test_is_xfr_enabled_close(run_mock):
    """Transferencia de zonas habilitado en server?."""
    assert not dns.is_xfr_enabled(TEST_ZONE, CONTAINER_IP)


# pylint: disable=unused-argument
def test_is_dynupdates_enabled_close(run_mock):
    """Actualizacion de zonas habilitado en server?."""
    assert not dns.is_dynupdate_enabled(TEST_ZONE, CONTAINER_IP)


# pylint: disable=unused-argument
def test_has_cache_poison_close(run_mock):
    """Server vulnerable a cache poison?."""
    assert not dns.has_cache_poison(TEST_ZONE, CONTAINER_IP)


# pylint: disable=unused-argument
def test_has_cache_snooping_close(run_mock):
    """Server vulnerable a cache snooping?."""
    assert not dns.has_cache_snooping(CONTAINER_IP)


# pylint: disable=unused-argument
def test_has_recursion_close(run_mock):
    """Server vulnerable a cache snooping?."""
    assert not dns.has_recursion(CONTAINER_IP)
