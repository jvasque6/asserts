# -*- coding: utf-8 -*-

"""Modulo para pruebas de captcha."""

# standard imports
from multiprocessing import Process
import time

# 3rd party imports
from test.mock import httpserver
import pytest

# local imports
from fluidasserts.format import captcha


# Constants

SECURE_CAPTCHA_IMG = ['test/provision/captcha/secure.jpg', '504375']
WEAK_CAPTCHA_IMG = ['test/provision/captcha/weak.jpg', 'WORDS']
SECURE_CAPTCHA_URL = ['http://127.0.0.1:5000/static/secure.jpg', '504375']
WEAK_CAPTCHA_URL = ['http://127.0.0.1:5000/static/weak.jpg', 'WORDS']


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

def test_is_insecure_in_image_open():
    """Insecure captcha open."""
    assert captcha.is_insecure_in_image(WEAK_CAPTCHA_IMG[0],
                                        WEAK_CAPTCHA_IMG[1])


@pytest.mark.usefixtures('mock_http')
def test_is_insecure_in_url_open():
    """Insecure captcha open."""
    assert captcha.is_insecure_in_url(WEAK_CAPTCHA_URL[0],
                                      WEAK_CAPTCHA_URL[1])

#
# Closing tests
#

def test_is_insecure_in_image_close():
    """Insecure captcha close."""
    assert not captcha.is_insecure_in_image(SECURE_CAPTCHA_IMG[0],
                                            SECURE_CAPTCHA_IMG[1])


@pytest.mark.usefixtures('mock_http')
def test_is_insecure_in_url_close():
    """Insecure captcha close."""
    assert not captcha.is_insecure_in_url(SECURE_CAPTCHA_URL[0],
                                          SECURE_CAPTCHA_URL[1])
