# -*- coding: utf-8 -*-

"""Modulo de configuración raiz de las pruebas de unidad.

Este modulo contiene los diferentes componentes reutilizables que requieren
las diferentes suites de pruebas.

https://pytest.org/dev/fixture.html
"""

# standard imports
import subprocess

# 3rd party imports
import pytest

# local imports
# none


@pytest.fixture(scope='session')
def container(request):
    """Inicia y detiene el contenedor docker que se usa para pruebas."""
    print('Prendiendo el contenedor')
    subprocess.call('test/container/start.sh \
                         test/container/conf.sh', shell=True)
    print('Configurando dinamicamente el ambiente base del contenedor')
    subprocess.call('ansible-playbook -vvv \
                         test/setup/os.yml', shell=True)
    subprocess.call('ansible-playbook \
                         test/setup/ftp.yml --tags basic', shell=True)

    def teardown():
        """Detiene el contenedor donde se ejecutan las pruebas."""
        print('Apagando el contenedor')
        subprocess.call('test/container/stop.sh \
                             test/container/conf.sh', shell=True)

    request.addfinalizer(teardown)
