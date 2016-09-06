# -*- coding: utf-8 -*-

"""Modulo de configuración raiz de las pruebas de unidad.

Este modulo contiene los diferentes componentes reutilizables que requieren
las diferentes suites de pruebas.

https://pytest.org/dev/fixture.html
"""

import time
# standard imports
from multiprocessing import Process
# local imports
from test.mock import httpserver

# 3rd party imports
import pytest


@pytest.fixture(scope='module')
def mock_http(request):
    """Inicia y detiene el servidor HTTP antes de ejecutar una prueba."""
    # Inicia el servidor HTTP en background
    prcs = Process(target=httpserver.start, name='MockHTTPServer')
    prcs.daemon = True
    prcs.start()

    # Espera que inicie servidor antes de recibir conexiones
    time.sleep(0.1)

    def teardown():
        """Detiene servidor HTTP al finalizar las pruebas."""
        prcs.terminate()
        request.addfinalizer(teardown)
