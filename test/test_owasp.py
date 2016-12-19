# -*- coding: utf-8 -*-

"""Modulo para pruebas de OWASP TOP 10.

Este modulo contiene las funciones necesarias
para probar OWASP TOP 10 2013 de aplicaciones.
"""

# standard imports
import subprocess
import time
from multiprocessing import Process

# 3rd party imports
import pytest

# local imports
from fluidasserts.helper import http_helper
from fluidasserts.service import http
from test.mock import httpserver

#
# Constants
#

CONTAINER_IP = '172.30.216.100'
BASE_URL = 'http://localhost:5000/http/headers'

#
# Fixtures
#


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


@pytest.fixture(scope='module')
def deploy_dvwa():
    """Despliega DVWA."""
    print('Deploying Damn Vulnerable Web Application')
    subprocess.call('ansible-playbook test/provision/dvwa.yml',
                    shell=True)


def get_dvwa_cookies():
    """Log in DVWA and return valid cookie."""
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
def test_owasp_A1_sqli_open():
    """App vulnerable a SQLi?"""
    dvwa_cookie = get_dvwa_cookies()
    dvwa_cookie['security'] = 'low'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/dvwa/vulnerabilities/sqli/'
    params = {'id': 'a\'', 'Submit': 'Submit'}

    expected = 'html'
    assert http.has_sqli(vulnerable_url, expected, params,
                         cookies=dvwa_cookie)


def test_owasp_A1_command_injection_open():
    """App vulnerable a command injection?"""
    dvwa_cookie = get_dvwa_cookies()
    dvwa_cookie['security'] = 'low'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/dvwa/vulnerabilities/exec/'
    data = 'ip=127.0.0.1%3Buname&Submit=Submit'

    expected = '<pre></pre>'
    assert http.has_command_injection(vulnerable_url, expected,
                                      params=None, data=data,
                                      cookies=dvwa_cookie)


@pytest.mark.usefixtures('mock_http')
def test_owasp_A2_sessionid_exposed_open():
    """Session ID expuesto?"""
    assert http.is_sessionid_exposed(
        '%s/sessionid_in_url' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_owasp_A2_session_fixation_open():
    """Session fixation posible?"""
    assert http.has_session_fixation(
        '%s/session_fixation_open' % (BASE_URL), 'Login required')



def test_owasp_A3_xss_open():
    """App vulnerable a XSS?"""
    dvwa_cookie = get_dvwa_cookies()
    dvwa_cookie['security'] = 'low'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/dvwa/vulnerabilities/xss_r/'
    params = {'name': '<script>alert(1)</script>'}

    expected = 'Hello alert'
    assert http.has_xss(vulnerable_url, expected, params,
                        cookies=dvwa_cookie)

#
# Close tests
#


def test_owasp_A1_sqli_close():
    """App vulnerable a SQLi?"""
    dvwa_cookie = get_dvwa_cookies()
    dvwa_cookie['security'] = 'medium'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/dvwa/vulnerabilities/sqli/'
    params = {'id': 'a\'', 'Submit': 'Submit'}

    expected = 'html'
    assert not http.has_sqli(vulnerable_url, expected, params,
                             cookies=dvwa_cookie)


def test_owasp_A1_command_injection_close():
    """App vulnerable a command injection?"""
    dvwa_cookie = get_dvwa_cookies()
    dvwa_cookie['security'] = 'medium'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/dvwa/vulnerabilities/exec/'
    data = 'ip=127.0.0.1%3Buname&Submit=Submit'

    expected = '<pre></pre>'
    assert not http.has_command_injection(vulnerable_url, expected,
                                          params=None, data=data,
                                          cookies=dvwa_cookie)


@pytest.mark.usefixtures('mock_http')
def test_owasp_A2_sessionid_exposed_close():
    """Session ID expuesto?"""
    assert not http.is_sessionid_exposed(
        '%s/sessionid_not_in_url' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_owasp_A2_session_fixation_close():
    """Session fixation posible?"""
    assert not http.has_session_fixation(
        '%s/session_fixation_close' % (BASE_URL), 'Login required')


def test_owasp_A3_xss_close():
    """App vulnerable a XSS?"""
    dvwa_cookie = get_dvwa_cookies()
    dvwa_cookie['security'] = 'medium'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/dvwa/vulnerabilities/xss_r/'
    params = {'name': '<script>alert(1)</script>'}

    expected = 'Hello alert'
    assert not http.has_xss(vulnerable_url, expected, params,
                            cookies=dvwa_cookie)
