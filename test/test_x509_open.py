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


# Constants

SSL_PORT = 443

#
# Open tests
#


@pytest.mark.parametrize('get_mock_ip', ['ssl_weak'], indirect=True)
def test_cn_equal_to_site_open(get_mock_ip):
    """CN del cert concuerda con el nombre del sitio?."""
    assert x509.is_cert_cn_not_equal_to_site(get_mock_ip)


def test_cert_lifespan_safe_open(get_mock_ip):
    """Vigencia del certificado es segura?."""
    assert x509.is_cert_validity_lifespan_unsafe(get_mock_ip)
