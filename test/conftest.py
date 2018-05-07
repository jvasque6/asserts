# -*- coding: utf-8 -*-

"""Unit test config module.

https://pytest.org/dev/fixture.html
"""

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
                 password=os.environ['DOCKER_PASS'])

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
    if ':' in mock:
        mock_dir = 'test/provision/' + mock.replace(':', '/')
    else:
        mock_dir = 'test/provision/' + mock

    client.images.build(path=mock_dir, tag=image)

    cont = client.containers.run(image,
                                 tty=True,
                                 detach=True)

    mynet.connect(cont)
    while True:
        con = client.containers.get(cont.id)
        c_ip = con.attrs['NetworkSettings']['Networks']\
            ['asserts_fluidasserts']['IPAddress']
        if c_ip:
            break

    for value in port_mapping.values():
        wait.tcp.open(int(value), host=c_ip, timeout=120)
        time.sleep(1)

    yield c_ip
    print('Stoping {} ...'.format(mock))
    cont.stop(timeout=1)
