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
from fluidasserts.service import http

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


def get_dvwa_cookies():
    login_url = 'http://' + CONTAINER_IP + '/dvwa/login.php'
    http_session = http_helper.HTTPSession(login_url)
    response = http_session.response

    csrf_token = http_helper.find_value_in_response(response.text,
                                                    'input',
                                                    'user_token')
    http_session.data = 'username=admin&\
        password=password&user_token=' + \
        csrf_token + '&Login=Login'

    successful_text = 'Welcome to Damn Vulnerable'
    http_session.formauth_by_response(successful_text)
    if not http_session.is_auth:
        return {}

    return http_session.cookies

#
# Open tests
#

@pytest.mark.usefixtures('container', 'deploy_dvwa')
def test_sqli_get_auth_open():
    dvwa_cookie = get_dvwa_cookies()
    dvwa_cookie['security'] = 'low'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/dvwa/vulnerabilities/sqli/'
    params = {'id': 'a\'', 'Submit': 'Submit'}

    assert http.has_sqli(vulnerable_url, params, 'html',
                         cookies=dvwa_cookie)

#
# Close tests
#


def test_sqli_get_auth_close():
    dvwa_cookie = get_dvwa_cookies()
    dvwa_cookie['security'] = 'impossible'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/dvwa/vulnerabilities/sqli/'
    params = {'id': 'a\'', 'Submit': 'Submit'}

    assert not http.has_sqli(vulnerable_url, params, 
                             'html', cookies=dvwa_cookie)
