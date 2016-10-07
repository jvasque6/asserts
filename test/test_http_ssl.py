# -*- coding: utf-8 -*-

"""Modulo para pruebas de SSL.

Este modulo contiene las funciones necesarias para probar si el modulo de
SSL se encuentra adecuadamente implementado.
"""

# standard imports
# none

# 3rd party imports
# none

# local imports
from fluidasserts import http_ssl


def test_http_ssl_is_cert_cn_equal_to_site():
    """CN del cert concuerda con el nombre del sitio?"""
    assert http_ssl.is_cert_cn_equal_to_site('fluid.la')


def test_http_ssl_is_pfs_enabled():
    """PFS habilitado en sitio?"""
    assert http_ssl.is_pfs_enabled('fluid.la')


def test_http_ssl_is_cert_active():
    """Certificado aun esta vigente?"""
    assert http_ssl.is_cert_active('fluid.la')


def test_http_ssl_is_cert_lifespan_safe():
    """Vigencia del certificado es segura?"""
    assert http_ssl.is_cert_validity_lifespan_safe('fluid.la')

# Pendente implementar resto de metodos
