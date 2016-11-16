# -*- coding: utf-8 -*-

"""

Modulo para pruebas de vulnerabilides en codigo HTML.

Este modulo contiene las funciones necesarias para probar si el modulo de
HTML se encuentra adecuadamente implementado.

Autor: Juan Escobar
Email: jescobar@fluid.la

"""

# standard imports

# 3rd party imports

# local imports
from fluidasserts import html


def test_form_autocomplete_open():
    """Verifica si el atributo autocomplete=off se encuentra en el
    codigo HTML de vulnerable.html"""
    assert html.has_not_autocomplete(
        'test/static/vulnerable.html',
        'body > form')


def test_form_autocomplete_close():
    """Verifica si el atributo autocomplete=off se encuentra en el
    codigo HTML de non-vulnerable.html?"""
    assert not html.has_not_autocomplete(
        'test/static/non-vulnerable.html',
        'body > form')

def test_is_cacheable_open():
    """Validar si las etiquetas que evitan que se almacene la pagina en
    memoria cache estan definidas en el codigo HTML de
    vulnerable.html"""
    assert html.is_cacheable('test/static/vulnerable.html')

def test_is_cacheable_close():
    """Validar si las etiquetas que evitan que se almacene la pagina en
    memoria cache estan definidas en el codigo HTML de
    non-vulnerable.html"""
    assert not html.is_cacheable('test/static/non-vulnerable.html')
