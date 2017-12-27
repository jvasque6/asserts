# -*- coding: utf-8 -*-

"""Modulo para pruebas de DNS.

Este modulo contiene las funciones necesarias para probar si el modulo de
DNS se encuentra adecuadamente implementado.
"""

# standard imports
from __future__ import print_function
import subprocess

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
# Open tests
#


@pytest.mark.parametrize('run_mock',
                         [('dns:weak', {'53/tcp': WEAK_PORT, '53/udp': WEAK_PORT})],
                         indirect=True)
def test_is_xfr_enabled_open(run_mock):
    """Transferencia de zonas habilitado en server?"""
    assert dns.is_xfr_enabled(TEST_ZONE, CONTAINER_IP)


# @pytest.mark.parametrize('run_mock',
                         # [('dns:weak', {'53/tcp': WEAK_PORT, '53/udp': WEAK_PORT})],
                         # indirect=True)
# def test_is_dynupdates_enabled_open(run_mock):
    # """Actualizacion de zonas habilitado en server?"""
    # assert dns.is_dynupdate_enabled(TEST_ZONE, CONTAINER_IP)


@pytest.mark.parametrize('run_mock',
                         [('dns:weak', {'53/tcp': WEAK_PORT, '53/udp': WEAK_PORT})],
                         indirect=True)
def test_has_cache_poison_open(run_mock):
    """Server vulnerable a cache poison?"""
    assert dns.has_cache_poison(TEST_ZONE, CONTAINER_IP)


@pytest.mark.parametrize('run_mock',
                         [('dns:weak', {'53/tcp': WEAK_PORT, '53/udp': WEAK_PORT})],
                         indirect=True)
def test_has_cache_snooping_open(run_mock):
    """Server vulnerable a cache snooping?"""
    assert dns.has_cache_snooping(CONTAINER_IP)


@pytest.mark.parametrize('run_mock',
                         [('dns:weak', {'53/tcp': WEAK_PORT, '53/udp': WEAK_PORT})],
                         indirect=True)
def test_has_recursion_open(run_mock):
    """Server has recursion enabled?"""
    assert dns.has_recursion(CONTAINER_IP)

