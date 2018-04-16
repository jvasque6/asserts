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
from fluidasserts.format import x509
import fluidasserts.utils.decorators

# Constants
fluidasserts.utils.decorators.UNITTEST = True
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
    assert not x509.is_cert_cn_not_equal_to_site(CONTAINER_IP)
    assert not x509.is_cert_cn_not_equal_to_site('0.0.0.0')


# pylint: disable=unused-argument
def test_cert_active_close(run_mock):
    """Certificado aun esta vigente?."""
    assert not x509.is_cert_inactive(CONTAINER_IP)


# pylint: disable=unused-argument
def test_cert_lifespan_safe_close(run_mock):
    """Vigencia del certificado es segura?."""
    assert not x509.is_cert_validity_lifespan_unsafe(CONTAINER_IP)


# pylint: disable=unused-argument
def test_is_sha1_used_close(run_mock):
    """Presencia de SHA1 en los algoritmos de cifrado?."""
    assert not x509.is_sha1_used(CONTAINER_IP, SSL_PORT)
    assert not x509.is_sha1_used('0.0.0.0', SSL_PORT)
