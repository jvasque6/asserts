# -*- coding: utf-8 -*-

"""Modulo para pruebas de SSL.

Este modulo contiene las funciones necesarias para probar si el modulo de
SSL se encuentra adecuadamente implementado.
"""

# standard imports
from __future__ import print_function
import subprocess

# 3rd party imports
import pytest

# local imports
from fluidasserts.service import ssl

# Constants
CONTAINER_IP = '172.30.216.101'
SSL_PORT = 443

#
# Open tests
#


@pytest.mark.parametrize('run_mock',
                         [('ssl:weak', {'443/tcp': SSL_PORT})],
                         indirect=True)
def test_cn_equal_to_site_open(run_mock):
    """CN del cert concuerda con el nombre del sitio?"""
    assert ssl.is_cert_cn_not_equal_to_site(CONTAINER_IP)


def test_pfs_enabled_open(run_mock):
    """PFS habilitado en sitio?"""
    assert ssl.is_pfs_disabled(CONTAINER_IP)


# There's no way to check this on Debian/Jessie because openssl dropped
# SSLv3 completely from that version on.
#
# @pytest.mark.usefixtures('container', 'weak_ssl')
# def test_sslv3_enabled_open():
#     """SSLv3 habilitado en sitio?"""
#     assert ssl.is_sslv3_enabled(CONTAINER_IP)


def test_tlsv1_enabled_open(run_mock):
    """TLSv1 habilitado en sitio?"""
    assert ssl.is_tlsv1_enabled(CONTAINER_IP)


def test_cert_lifespan_safe_open(run_mock):
    """Vigencia del certificado es segura?"""
    assert ssl.is_cert_validity_lifespan_unsafe(CONTAINER_IP)
