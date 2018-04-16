# -*- coding: utf-8 -*-

"""Modulo para pruebas de SSL.

Este modulo contiene las funciones necesarias para probar si el modulo de
SSL se encuentra adecuadamente implementado.
"""

# standard imports
from __future__ import print_function

# 3rd party imports
import pytest

# local imports
from fluidasserts.service import ssl
import fluidasserts.utils.decorators

# Constants
fluidasserts.utils.decorators.UNITTEST = True
CONTAINER_IP = '172.30.216.101'
SSL_PORT = 443

#
# Open tests
#


@pytest.mark.parametrize('run_mock',
                         [('ssl:weak', {'443/tcp': SSL_PORT})],
                         indirect=True)
# pylint: disable=unused-argument
def test_pfs_enabled_open(run_mock):
    """PFS habilitado en sitio?."""
    assert ssl.is_pfs_disabled(CONTAINER_IP)


# pylint: disable=unused-argument
def test_sslv3_enabled_open():
    """SSLv3 habilitado en sitio?."""
    assert ssl.is_sslv3_enabled(CONTAINER_IP)


# pylint: disable=unused-argument
def test_tlsv1_enabled_open(run_mock):
    """TLSv1 habilitado en sitio?."""
    assert ssl.is_tlsv1_enabled(CONTAINER_IP)


# pylint: disable=unused-argument
def test_has_poodle_sslv3_open():
    """Sitio vulnerable a POODLE?."""
    assert ssl.has_poodle_sslv3(CONTAINER_IP)


# pylint: disable=unused-argument
def test_has_beast_open():
    """Sitio vulnerable a BEAST?."""
    assert ssl.has_beast(CONTAINER_IP)


# pylint: disable=unused-argument
def test_allows_weak_alg_open():
    """Sitio permite algoritmos debiles?."""
    assert ssl.allows_weak_ciphers(CONTAINER_IP)


# pylint: disable=unused-argument
def test_allows_anon_alg_open():
    """Sitio permite algoritmos anonimos?."""
    assert ssl.allows_anon_ciphers(CONTAINER_IP)
