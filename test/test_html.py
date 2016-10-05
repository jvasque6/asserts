# -*- coding: utf-8 -*-

"""

Modulo para pruebas de vulnerabilides en código HTML.

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
    """Attribute autocomplete=off in vulnerable.html?"""
    assert html.form_autocomplete(
        'test/static/vulnerable.html',
        'body > form')


def test_form_autocomplete_close():
    """Attribute autocomplete=off in no-vulnerable.html?"""
    assert not html.form_autocomplete(
        'test/static/non-vulnerable.html',
        'body > form')
