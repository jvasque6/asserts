# -*- coding: utf-8 -*-

"""Modulo para pruebas de cookie.

Este modulo contiene las funciones necesarias para probar si el modulo de
HTTP se encuentra adecuadamente implementado.
"""

# standard imports
from __future__ import print_function

# 3rd party imports
# None

# local imports
from fluidasserts.format import cookie
from fluidasserts.helper import http_helper

#
# Constants
#
MOCK_SERVICE = 'http://localhost:5000'
NON_EXISTANT = 'https://nonexistant.fluidattacks.com'


def test_has_not_secure_set_open():
    """Cookie has secure attribute?."""
    url = '%s/http/cookies/secure/fail' % (MOCK_SERVICE)
    cookie_name = 'JSESSID'
    assert cookie.has_not_secure_set(cookie_name, url)


def test_has_not_secure_set_close():
    """Cookie has secure attribute?."""
    url = '%s/http/cookies/secure/ok' % (MOCK_SERVICE)
    cookie_name = 'JSESSID'
    assert not cookie.has_not_secure_set(cookie_name, url)
    assert not cookie.has_not_secure_set(cookie_name, NON_EXISTANT)


def test_has_not_httponly_set_open():
    """Cookie has http-only attribute?."""
    url = '%s/http/cookies/http_only/fail' % (MOCK_SERVICE)
    cookie_name = 'JSESSID'
    assert cookie.has_not_httponly_set(cookie_name, url)


def test_has_not_httponly_set_close():
    """Cookie has http-only attribute?."""
    url = '%s/http/cookies/http_only/ok' % (MOCK_SERVICE)
    cookie_name = 'JSESSID'
    assert not cookie.has_not_httponly_set(cookie_name, url)
    assert not cookie.has_not_httponly_set(cookie_name, NON_EXISTANT)


def test_has_not_httponly_in_cookiejar_open():
    """Cookiejar has http-only attribute?."""
    url = '%s/http/cookies/http_only/fail' % (MOCK_SERVICE)
    cookie_name = 'JSESSID'
    sess = http_helper.HTTPSession(url)
    assert cookie.has_not_httponly_in_cookiejar(cookie_name, sess.cookies)


def test_has_not_httponly_in_cookiejar_close():
    """Cookiejar has http-only attribute?."""
    url = '%s/http/cookies/http_only/ok' % (MOCK_SERVICE)
    cookie_name = 'JSESSID'
    sess = http_helper.HTTPSession(url)
    assert not cookie.has_not_httponly_in_cookiejar(cookie_name, sess.cookies)
    assert not cookie.has_not_httponly_in_cookiejar(cookie_name, None)
    assert not cookie.has_not_httponly_in_cookiejar(None, sess.cookies)


def test_has_not_secure_in_cookiejar_open():
    """Cookiejar has secure attribute?."""
    url = '%s/http/cookies/secure/fail' % (MOCK_SERVICE)
    cookie_name = 'JSESSID'
    sess = http_helper.HTTPSession(url)
    assert cookie.has_not_secure_in_cookiejar(cookie_name, sess.cookies)


def test_has_not_secure_in_cookiejar_close():
    """Cookiejar has secure attribute?."""
    url = '%s/http/cookies/secure/ok' % (MOCK_SERVICE)
    cookie_name = 'JSESSID'
    sess = http_helper.HTTPSession(url)
    assert not cookie.has_not_secure_in_cookiejar(cookie_name, sess.cookies)
    assert not cookie.has_not_secure_in_cookiejar(cookie_name, None)
    assert not  cookie.has_not_secure_in_cookiejar(None, sess.cookies)
