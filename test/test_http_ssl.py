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

# Pendente implementar resto de metodos
