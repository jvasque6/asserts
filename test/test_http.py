# -*- coding: utf-8 -*-

"""Modulo para pruebas de HTTP.

Este modulo contiene las funciones necesarias para probar si el modulo de
HTTP se encuentra adecuadamente implementado.

Adicionalmente es desde este modulo que se realiza el encendido y apagado
del servicio MOCK que simula varios de los problemas y las correcciones
propias de HTTP.
"""

# standard imports
# none

# 3rd party imports
import pytest

# local imports
from fluidasserts import http


BASE_URL = 'http://localhost:5000/http/headers'


@pytest.fixture(scope='module')
def mock(request):
    """Inicia y detiene el servidor HTTP antes de ejecutar una prueba"""
    from multiprocessing import Process
    from test.mock import httpserver
    import time

    """Inicia el servidor HTTP en background"""
    mock = Process(target=httpserver.start, name="MockHTTPServer")
    mock.daemon = True
    mock.start()

    """Espera unos instantes a que inicie el servidor antes de empezar a
    a recibir conexiones
    """
    time.sleep(0.1)

    """Este metodo detiene el servidor HTTP cuando los tests han finalizado"""
    def teardown():
        mock.terminate()
        request.addfinalizer(teardown)


def test_access_control_allow_origin_open(mock):
    """Header Access-Control-Allow-Origin no establecido?"""
    assert http.has_header_access_control_allow_origin(
        '%s/access_control_allow_origin/fail' % (BASE_URL))


def test_access_control_allow_origin_close(mock):
    """Header Access-Control-Allow-Origin establecido?"""
    assert not http.has_header_access_control_allow_origin(
        '%s/access_control_allow_origin/ok' % (BASE_URL))


def test_cache_control_open(mock):
    """Header Cache-Control no establecido?"""
    assert http.has_header_cache_control(
        '%s/cache_control/fail' % (BASE_URL))


def test_cache_control_close(mock):
    """Header Cache-Control establecido?"""
    assert not http.has_header_cache_control(
        '%s/cache_control/ok' % (BASE_URL))

#
# TODO(glopez) Functions in HTTP library
#
# http.has_header_x_xxs_protection('%s/access_control_allow_origin/fail'
#   % (BASE_URL))
# http.has_header_x_xxs_protection("http://challengeland.co/")
# http.has_header_x_frame_options("http://localhost/cursos")
# http.has_header_x_frame_options("http://challengeland.co/")
# http.has_header_x_permitted_cross_domain_policies("http://localhost/cursos")
# http.has_header_x_permitted_cross_domain_policies("http://challengeland.co/")
# http.has_header_x_content_type_options("http://localhost/cursos")
# http.has_header_x_content_type_options("http://challengeland.co")
# http.has_header_pragma("http://localhost/cursos")
# http.has_header_pragma("http://challengeland.co")
# http.has_header_expires("http://localhost/cursos")
# http.has_header_expires("http://challengeland.co")
# http.has_header_pragma("http://localhost/cursos")
# http.has_header_content_type("http://challengeland.co")
# http.has_header_content_security_policy("http://challengeland.co")
# http.has_header_content_security_policy("http://localhost/cursos")
# cookie.has_http_only("http://challengeland.co","ci_session")
# http.basic_auth("http://localhost/fluidopens/BasicAuth/","root","1234")
# http.basic_auth("http://localhost/fluidopens/BasicAuth/","Admin","1234")
# Asymetric testing
# http.response_is_stable(seconds, URL, repeat)
