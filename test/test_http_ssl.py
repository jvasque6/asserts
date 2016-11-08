# -*- coding: utf-8 -*-

"""Modulo para pruebas de SSL.

Este modulo contiene las funciones necesarias para probar si el modulo de
SSL se encuentra adecuadamente implementado.
"""

# standard imports
import subprocess

# 3rd party imports
import pytest

# local imports
from fluidasserts import http_ssl

# Constants
CONTAINER_IP = '172.30.216.100'


#
# Fixtures
#


# pylint: disable=unused-argument
@pytest.fixture(scope='module')
def weak_ssl(request):
    """Configura perfil de HTTPS vulnerable."""
    print('Running HTTP_SSL vulnerable playbook')
    subprocess.call('ansible-playbook test/provision/web-tls.yml \
            --tags basic,weak', shell=True)


# pylint: disable=unused-argument
@pytest.fixture(scope='module')
def hard_ssl(request):
    """Configura perfil de HTTPS endurecido."""
    print('Running HTTP_SSL hardened playbook')
    subprocess.call('ansible-playbook test/provision/web-tls.yml \
            --tags basic,hard', shell=True)


#
# Open tests
#


@pytest.mark.usefixtures('container', 'weak_ssl')
def test_httpssl_cert_cn_equal_to_site_open():
    """CN del cert concuerda con el nombre del sitio?"""
    assert http_ssl.is_cert_cn_not_equal_to_site(CONTAINER_IP)


@pytest.mark.usefixtures('container', 'weak_ssl')
def test_httpssl_pfs_enabled_open():
    """PFS habilitado en sitio?"""
    assert http_ssl.is_pfs_disabled(CONTAINER_IP)


@pytest.mark.usefixtures('container', 'weak_ssl')
def test_httpssl_sslv3_enabled_open():
    """SSLv3 habilitado en sitio?"""
    assert http_ssl.is_sslv3_tlsv1_enabled(CONTAINER_IP)


#@pytest.mark.usefixtures('container', 'weak_ssl')
#def test_httpssl_cert_active_open():
#    """Certificado aun esta vigente?"""
#    assert http_ssl.is_cert_inactive(CONTAINER_IP)


@pytest.mark.usefixtures('container', 'weak_ssl')
def test_httpssl_cert_lifespan_safe_open():
    """Vigencia del certificado es segura?"""
    assert http_ssl.is_cert_validity_lifespan_unsafe(CONTAINER_IP)

#
# Closing tests
#


@pytest.mark.usefixtures('container', 'hard_ssl')
def test_httpssl_cert_cn_equal_to_site_close():
    """CN del cert concuerda con el nombre del sitio?"""
    assert not http_ssl.is_cert_cn_not_equal_to_site(CONTAINER_IP)


@pytest.mark.usefixtures('container', 'hard_ssl')
def test_httpssl_pfs_enabled_close():
    """PFS habilitado en sitio?"""
    assert not http_ssl.is_pfs_disabled(CONTAINER_IP)


@pytest.mark.usefixtures('container', 'hard_ssl')
def test_httpssl_sslv3_enabled_close():
    """SSLv3 habilitado en sitio?"""
    assert not http_ssl.is_sslv3_tlsv1_enabled(CONTAINER_IP)


@pytest.mark.usefixtures('container', 'hard_ssl')
def test_httpssl_cert_active_close():
    """Certificado aun esta vigente?"""
    assert not http_ssl.is_cert_inactive(CONTAINER_IP)


@pytest.mark.usefixtures('container', 'hard_ssl')
def test_httpssl_cert_lifespan_safe_close():
    """Vigencia del certificado es segura?"""
    assert not http_ssl.is_cert_validity_lifespan_unsafe(CONTAINER_IP)

# Pendente implementar resto de metodos
