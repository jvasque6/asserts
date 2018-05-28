# -*- coding: utf-8 -*-

"""Modulo para pruebas de cookie.

Este modulo contiene las funciones necesarias para probar si el modulo de
HTTP se encuentra adecuadamente implementado.
"""

# standard imports
from __future__ import print_function
from multiprocessing import Process
import time

# 3rd party imports
from test.mock import httpserver
import pytest

# local imports
from fluidasserts.format import cookie
from fluidasserts.helper import http_helper

#
# Constants
#
MOCK_SERVICE = 'http://localhost:5000'
NON_EXISTANT = 'https://nonexistant.fluidattacks.com'


@pytest.fixture(scope='module')
def mock_http(request):
    """Inicia y detiene el servidor HTTP antes de ejecutar una prueba."""
    # Inicia el servidor HTTP en background
    prcs = Process(target=httpserver.start, name='MockHTTPServer')
    prcs.daemon = True
    prcs.start()

    # Espera que inicie servidor antes de recibir conexiones
    time.sleep(0.5)

    def teardown():
        """Detiene servidor HTTP al finalizar las pruebas."""
        prcs.terminate()

    request.addfinalizer(teardown)


@pytest.mark.usefixtures('mock_http')
def test_has_not_secure_set_open():
    """Cookie has secure attribute?."""
    url = '%s/http/cookies/secure/fail' % (MOCK_SERVICE)
    cookie_name = 'JSESSID'
    assert cookie.has_not_secure_set(cookie_name, url)


@pytest.mark.usefixtures('mock_http')
def test_has_not_secure_set_close():
    """Cookie has secure attribute?."""
    url = '%s/http/cookies/secure/ok' % (MOCK_SERVICE)
    cookie_name = 'JSESSID'
    assert not cookie.has_not_secure_set(cookie_name, url)
    assert not cookie.has_not_secure_set(cookie_name, NON_EXISTANT)


@pytest.mark.usefixtures('mock_http')
def test_has_not_httponly_set_open():
    """Cookie has http-only attribute?."""
    url = '%s/http/cookies/http_only/fail' % (MOCK_SERVICE)
    cookie_name = 'JSESSID'
    assert cookie.has_not_httponly_set(cookie_name, url)


@pytest.mark.usefixtures('mock_http')
def test_has_not_httponly_set_close():
    """Cookie has http-only attribute?."""
    url = '%s/http/cookies/http_only/ok' % (MOCK_SERVICE)
    cookie_name = 'JSESSID'
    assert not cookie.has_not_httponly_set(cookie_name, url)
    assert not cookie.has_not_httponly_set(cookie_name, NON_EXISTANT)


@pytest.mark.usefixtures('mock_http')
def test_has_not_httponly_in_cookiejar_open():
    """Cookiejar has http-only attribute?."""
    url = '%s/http/cookies/http_only/fail' % (MOCK_SERVICE)
    cookie_name = 'JSESSID'
    sess = http_helper.HTTPSession(url)
    assert cookie.has_not_httponly_in_cookiejar(cookie_name, sess.cookies)



@pytest.mark.usefixtures('mock_http')
def test_has_not_httponly_in_cookiejar_close():
    """Cookiejar has http-only attribute?."""
    url = '%s/http/cookies/http_only/ok' % (MOCK_SERVICE)
    cookie_name = 'JSESSID'
    sess = http_helper.HTTPSession(url)
    assert not cookie.has_not_httponly_in_cookiejar(cookie_name, sess.cookies)
    assert not cookie.has_not_httponly_in_cookiejar(cookie_name, None)
    assert not cookie.has_not_httponly_in_cookiejar(None, sess.cookies)


@pytest.mark.usefixtures('mock_http')
def test_has_not_secure_in_cookiejar_open():
    """Cookiejar has secure attribute?."""
    url = '%s/http/cookies/secure/fail' % (MOCK_SERVICE)
    cookie_name = 'JSESSID'
    sess = http_helper.HTTPSession(url)
    assert cookie.has_not_secure_in_cookiejar(cookie_name, sess.cookies)


@pytest.mark.usefixtures('mock_http')
def test_has_not_secure_in_cookiejar_close():
    """Cookiejar has secure attribute?."""
    url = '%s/http/cookies/secure/ok' % (MOCK_SERVICE)
    cookie_name = 'JSESSID'
    sess = http_helper.HTTPSession(url)
    assert not cookie.has_not_secure_in_cookiejar(cookie_name, sess.cookies)
    assert not cookie.has_not_secure_in_cookiejar(cookie_name, None)
    assert not  cookie.has_not_secure_in_cookiejar(None, sess.cookies)
