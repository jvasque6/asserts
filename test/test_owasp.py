# -*- coding: utf-8 -*-

"""Modulo para pruebas de OWASP TOP 10.

Este modulo contiene las funciones necesarias
para probar OWASP TOP 10 2013 de aplicaciones.
"""

# standard imports
import subprocess

# 3rd party imports
import pytest

# local imports
from fluidasserts.helper import http_helper

#
# Constants
#

CONTAINER_IP = '172.30.216.100'

#
# Fixtures
#


@pytest.fixture(scope='module')
def deploy_dvwa():
    """Despliega DVWA."""
    print('Deploying Damn Vulnerable Web Application')
    subprocess.call('ansible-playbook test/provision/dvwa.yml',
                    shell=True)
#
# Open tests
#


@pytest.mark.usefixtures('container', 'deploy_dvwa')
@http_helper.dvwa_vuln('SQLi', host=CONTAINER_IP, level='weak')
@http_helper.http_app('DVWA', host=CONTAINER_IP)
def test_sqli_open(**kwargs):
    assert http_helper.generic_http_assert(**kwargs)

#
# Close tests
#


@http_helper.dvwa_vuln('SQLi', host=CONTAINER_IP, level='hard')
@http_helper.http_app('DVWA', host=CONTAINER_IP)
def test_sqli_close(**kwargs):
    assert not http_helper.generic_http_assert(**kwargs)
