# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.code.docker."""

# standard imports
from multiprocessing import Process
import time

# 3rd party imports
from test.mock import httpserver
import pytest

# local imports
from fluidasserts.proto import rest


# Constants

MOCK_SERVICE = 'http://localhost:5000'
BASE_URL = MOCK_SERVICE + '/rest'
BWAPP_PORT = 80
NONEXISTANT_SERVICE = 'http://nonexistant.fluidattacks.com'


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

#
# Open tests
#


@pytest.mark.usefixtures('mock_http')
def test_has_access_open():
    """Resource is available?."""
    assert rest.has_access(BASE_URL + '/access/fail')


@pytest.mark.usefixtures('mock_http')
def test_content_type_open():
    """Resource is available?."""
    assert rest.accepts_empty_content_type(
        BASE_URL + '/content_type/fail')


@pytest.mark.usefixtures('mock_http')
def test_insecure_accept_open():
    """Resource is available?."""
    assert rest.accepts_insecure_accept_header(
        BASE_URL + '/insecure_accept/fail')

#
# Closing tests
#


@pytest.mark.usefixtures('mock_http')
def test_has_access_close():
    """Resource is available?."""
    assert not rest.has_access(BASE_URL + '/access/ok')


@pytest.mark.usefixtures('mock_http')
def test_content_type_close():
    """Resource is available?."""
    assert not rest.accepts_empty_content_type(
        BASE_URL + '/content_type/ok')


@pytest.mark.usefixtures('mock_http')
def test_insecure_accept_close():
    """Resource is available?."""
    assert not rest.accepts_insecure_accept_header(
        BASE_URL + '/insecure_accept/ok')