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
import fluidasserts.utils.decorators

# Constants
fluidasserts.utils.decorators.UNITTEST = True
TEST_ZONE = 'fluid.la'
WEAK_PORT = 53
HARD_PORT = 53


#
# Open tests
#


@pytest.mark.parametrize('run_mock',
                         [('dns:weak', {'53/tcp': WEAK_PORT,
                                        '53/udp': WEAK_PORT})],
                         indirect=True)
def test_is_xfr_enabled_open(run_mock):
    """Transferencia de zonas habilitado en server?."""
    assert dns.is_xfr_enabled(TEST_ZONE, run_mock)


def test_has_cache_poison_open(run_mock):
    """Server vulnerable a cache poison?."""
    assert dns.has_cache_poison(TEST_ZONE, run_mock)


def test_has_cache_snooping_open(run_mock):
    """Server vulnerable a cache snooping?."""
    assert dns.has_cache_snooping(run_mock)


def test_has_recursion_open(run_mock):
    """Server has recursion enabled?."""
    assert dns.has_recursion(run_mock)


def test_can_amplify_open(run_mock):
    """Server can perform DNS amplification attacks?."""
    assert dns.can_amplify(run_mock)
