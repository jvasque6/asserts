# -*- coding: utf-8 -*-

"""Unit test config module."""

# standard imports
from __future__ import print_function
import os
import time

# 3rd party imports
import docker
import pytest
import wait

# local imports
# none

# Constants
NETWORK_NAME = 'bridge'


@pytest.fixture(scope='module')
def run_mock(request):
    """Run mock with given parameters."""
    mock = request.param[0]
    port_mapping = request.param[1]
    print('Running {} ... '.format(mock))

    client = docker.from_env()

    client.login(registry='registry.gitlab.com',
                 username=os.environ['DOCKER_USER'],
                 password=os.environ['DOCKER_PASS'])

    image = 'registry.gitlab.com/fluidsignal/asserts/mocks/' + mock
    if ':' in mock:
        mock_dir = 'test/provision/' + mock.replace(':', '/')
    else:
        mock_dir = 'test/provision/' + mock

    client.images.build(path=mock_dir, tag=image)

    cont = client.containers.run(image,
                                 tty=True,
                                 detach=True)

    while True:
        con = client.containers.get(cont.id)
        c_ip = con.attrs['NetworkSettings']['Networks']\
            ['bridge']['IPAddress']
        if c_ip:
            break

    for value in port_mapping.values():
        wait.tcp.open(value, c_ip, timeout=30)
        time.sleep(2)

    yield c_ip
    print('Stoping {} ...'.format(mock))
    cont.stop(timeout=10)
