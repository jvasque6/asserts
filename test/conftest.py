# -*- coding: utf-8 -*-

"""Unit test config module.

https://pytest.org/dev/fixture.html
"""

# standard imports
from __future__ import print_function
import errno
import os
import socket
import time

# 3rd party imports
import docker
import pytest

# local imports
# none

# Constants
NETWORK_NAME = 'bridge'
NETWORK_SUBNET = '172.30.216.0/24'
NETWORK_GW = '172.30.216.254'


def wait_net_service(server, port, timeout=None):
    """
    Wait for network service to appear.

    @param timeout: in seconds, if None or 0 wait forever
    @return: True of False, if timeout is None may return only True or
             throw unhandled network exception
    """
    sock = socket.socket()
    if timeout:
        from time import time as now
        end = now() + timeout

    while True:
        try:
            if timeout:
                next_timeout = end - now()
                if next_timeout < 0:
                    return False
                else:
                    sock.settimeout(next_timeout)

            sock.connect((server, port))

        except socket.timeout:
            if timeout:
                return False

        except socket.error as err:
            if not isinstance(err.args, tuple) or err.errno != errno.ETIMEDOUT:
                pass
            else:
                raise
        else:
            sock.close()
            return True


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
            ['asserts_fluidasserts']['IPAddress']
        if c_ip:
            break

    for value in port_mapping.values():
        wait_net_service(c_ip, value, 30)
        time.sleep(2)

    yield c_ip
    print('Stoping {} ...'.format(mock))
    cont.stop(timeout=10)
