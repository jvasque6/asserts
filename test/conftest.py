# -*- coding: utf-8 -*-

"""Modulo de configuración raiz de las pruebas de unidad.

Este modulo contiene los diferentes componentes reutilizables que requieren
las diferentes suites de pruebas.

https://pytest.org/dev/fixture.html
"""

# standard imports
from __future__ import print_function
import os
import time
import subprocess

# 3rd party imports
import docker
import pytest
import wait

# local imports
# none

# Constants
NETWORK_NAME = 'asserts_fluidasserts'
NETWORK_SUBNET = '172.30.216.0/24'
NETWORK_GW = '172.30.216.254'
CONTAINER_IP = '172.30.216.101'


@pytest.fixture(scope='module')
def run_mock(request):
    """Configura perfil de SMTP vulnerable."""
    print('Running SMTP vulnerable playbook')

    mock = request.param[0]
    port_mapping = request.param[1]

    client = docker.from_env()

    client.login(registry='registry.gitlab.com',
                 username=os.environ['DOCKER_USER'],
                 password=os.environ['DOCKER_PASS']
                 )

    try:
        ipam_pool = docker.types.IPAMPool(subnet=NETWORK_SUBNET,
                                          gateway=NETWORK_GW)
        ipam_config = docker.types.IPAMConfig(pool_configs=[ipam_pool])
        mynet = client.networks.create(NETWORK_NAME,
                                       driver="bridge",
                                       ipam=ipam_config)
    except docker.errors.APIError:
        mynet = client.networks.list(names=NETWORK_NAME)[0]

    image = 'registry.gitlab.com/fluidsignal/asserts/mocks/' + mock
    cont = client.containers.run(image,
                                 ports=port_mapping,
                                 detach=True)

    mynet.connect(cont, ipv4_address=CONTAINER_IP)

    for value in port_mapping.values():
        wait.tcp.open(int(value), host=CONTAINER_IP, timeout=10)
        time.sleep(1)

    def teardown():
        """Detiene el contenedor."""
        cont.stop(timeout=1)
    request.addfinalizer(teardown)
