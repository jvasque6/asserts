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
@http_helper.sqli_engine('MySQL')
@http_helper.sqli_app('DVWA', host=CONTAINER_IP, level='weak')
def test_sqli_open(**kw):
    assert http_helper.generic_http_assert(**kw)

#
# Close tests
#


@http_helper.sqli_engine('MySQL')
@http_helper.sqli_app('DVWA', host=CONTAINER_IP, level='hard')
def test_sqli_close(**kw):
    assert not http_helper.generic_http_assert(**kw)
