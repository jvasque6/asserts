# -*- coding: utf-8 -*-

"""Modulo para pruebas de vulnerabilides en codigo HTML.

Este modulo contiene las funciones necesarias para probar si el modulo de
HTML se encuentra adecuadamente implementado.
"""

# standard imports

# 3rd party imports

# local imports
from fluidasserts.lang import html


# Constants


CODE_DIR = 'test/static/lang/html/'
SECURE_CODE = CODE_DIR + 'non-vulnerable.html'
INSECURE_CODE = CODE_DIR + 'vulnerable.html'
NOT_CODE = CODE_DIR + 'notexists.html'

#
# Open tests
#


def test_form_autocomplete_open():
    """Funcion test_form_autocomplete_open.

    Verifica si el atributo autocomplete=off se encuentra en el
    codigo HTML de vulnerable.html
    """
    assert html.has_not_autocomplete(INSECURE_CODE)


def test_is_cacheable_open():
    """Funcion test_is_cacheable_open.

    Validar si las etiquetas que evitan que se almacene la pagina en
    memoria cache estan definidas en el codigo HTML de
    vulnerable.html
    """
    assert html.is_cacheable(INSECURE_CODE)


def test_is_header_content_type_missing_open():
    """Funcion test_is_header_content_type_missing_open.

    Validar si las etiquetas que establecen la cabecera Content-Type
    estan definidas en el codigo HTML de vulnerable.html
    """
    assert html.is_header_content_type_missing(INSECURE_CODE)


#
# Closing tests
#


def test_form_autocomplete_close():
    """Funcion test_form_autocomplete_close.

    Verifica si el atributo autocomplete=off se encuentra en el
    codigo HTML de non-vulnerable.html?
    """
    assert not html.has_not_autocomplete(SECURE_CODE)
    assert not html.has_not_autocomplete(NOT_CODE)


def test_is_cacheable_close():
    """Funcion test_is_cacheable_close.

    Validar si las etiquetas que evitan que se almacene la pagina en
    memoria cache estan definidas en el codigo HTML de
    non-vulnerable.html
    """
    assert not html.is_cacheable(SECURE_CODE)
    assert not html.is_cacheable(NOT_CODE)


def test_is_header_content_type_missing_close():
    """Funcion test_is_header_content_type_missing_open.

    Validar si las etiquetas que establecen la cabecera Content-Type
    estan definidas en el codigo HTML de non-vulnerable.html
    """
    assert not html.is_header_content_type_missing(SECURE_CODE)
    assert not html.is_header_content_type_missing(NOT_CODE)
