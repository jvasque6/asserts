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

# Constants
CONTAINER_IP = '172.30.216.101'
SSL_PORT = 443

#
# Closing tests
#


@pytest.mark.parametrize('run_mock',
                         [('ssl:hard', {'443/tcp': SSL_PORT})],
                         indirect=True)
# pylint: disable=unused-argument
def test_cn_equal_to_site_close(run_mock):
    """CN del cert concuerda con el nombre del sitio?."""
    assert not ssl.is_cert_cn_not_equal_to_site(CONTAINER_IP)


# pylint: disable=unused-argument
def test_pfs_enabled_close(run_mock):
    """PFS habilitado en sitio?."""
    assert not ssl.is_pfs_disabled(CONTAINER_IP)


# pylint: disable=unused-argument
def test_sslv3_enabled_close(run_mock):
    """SSLv3 habilitado en sitio?."""
    assert not ssl.is_sslv3_enabled(CONTAINER_IP)


# pylint: disable=unused-argument
def test_tlsv1_enabled_close(run_mock):
    """TLSv1 habilitado en sitio?."""
    assert not ssl.is_tlsv1_enabled(CONTAINER_IP)


# pylint: disable=unused-argument
def test_cert_active_close(run_mock):
    """Certificado aun esta vigente?."""
    assert not ssl.is_cert_inactive(CONTAINER_IP)


# pylint: disable=unused-argument
def test_cert_lifespan_safe_close(run_mock):
    """Vigencia del certificado es segura?."""
    assert not ssl.is_cert_validity_lifespan_unsafe(CONTAINER_IP)
