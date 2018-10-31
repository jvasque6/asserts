# -*- coding: utf-8 -*-

"""Unit test config module."""

# standard imports
from __future__ import print_function
import os

# 3rd party imports
import docker
import pytest
import wait

# local imports
# none

# Constants
NETWORK_NAME = 'bridge'


def get_ip(mock):
    """Get mock IP."""
    client = docker.from_env()
    con = client.containers.get(mock)
    return con.attrs['NetworkSettings']['Networks']\
        ['bridge']['IPAddress']


@pytest.fixture(scope='session', autouse=True)
def run_mocks(request):
    """Run mock with given parameters."""
    mocks = {
        'bwapp': {'80/tcp': 80},
        'mysql_db:weak': {'3306/tcp': 3306},
        'mysql_db:hard': {'3306/tcp': 3306},
        'ssl:weak': {'443/tcp': 443},
        'ssl:hard': {'443/tcp': 443},
        'tcp:weak': {'21/tcp': 21},
        'tcp:hard': {'443/tcp': 443},
        'dns:hard': {'53/tcp': 53, '53/udp': 53},
        'dns:weak': {'53/tcp': 53, '53/udp': 53},
        #'ftp:weak': {'21/tcp': 21},
        #'ftp:hard': {'21/tcp': 21},
        'ldap:weak': {'389/tcp': 389},
        'ldap:hard': {'389/tcp': 389},
        'mysql_os:weak': {'22/tcp': 22},
        'mysql_os:hard': {'22/tcp': 22},
        'os:weak': {'22/tcp': 22},
        'os:hard': {'22/tcp': 22},
        'smb:weak': {'139/tcp': 139},
        'smb:hard': {'139/tcp': 139},
        'smtp:weak': {'25/tcp': 25},
        'smtp:hard': {'25/tcp': 25},
    }

    client = docker.from_env()

    client.login(registry='registry.gitlab.com',
                username=os.environ['DOCKER_USER'],
                password=os.environ['DOCKER_PASS'])

    for mock, _ in mocks.items():
        try:
            mock_name = mock.replace(':', '_')
            cont = client.containers.get(mock_name)
            cont.remove(force=True)
        except docker.errors.NotFound:
            pass

    for mock, port_mapping in mocks.items():
        print('Running {} ... '.format(mock))

        image = 'registry.gitlab.com/fluidsignal/asserts/mocks/' + mock
        if ':' in mock:
            mock_dir = 'test/provision/' + mock.replace(':', '/')
        else:
            mock_dir = 'test/provision/' + mock

        mock_name = mock.replace(':', '_')

        client.images.build(path=mock_dir, tag=image)

        client.containers.run(image, name=mock_name, tty=True, detach=True)

    for mock, port_mapping in mocks.items():
        ip = get_ip(mock.replace(':', '_'))
        for value in port_mapping.values():
            wait.tcp.open(value, ip, timeout=30)

    yield ip
    for mock, _ in mocks.items():
        mock_name = mock.replace(':', '_')
        cont = client.containers.get(mock_name)
        cont.remove(force=True)


@pytest.fixture(scope='module')
def get_mock_ip(request):
    """Run mock with given parameters."""
    mock = request.param
    print('Running {} ... '.format(mock))
    yield get_ip(mock)
