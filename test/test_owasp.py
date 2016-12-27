# -*- coding: utf-8 -*-

"""Modulo para pruebas de OWASP TOP 10.

Este modulo contiene las funciones necesarias
para probar OWASP TOP 10 2013 de aplicaciones.
"""

# standard imports
from __future__ import print_function
from multiprocessing import Process
import subprocess
import time

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
def deploy_bwapp():
    """Despliega bWAPP."""
    print('Deploying bWAPP')
    subprocess.call('ansible-playbook test/provision/bwapp.yml',
                    shell=True)


def get_bwapp_cookies():
    """Log in to bWAPP and return valid cookie."""
    login_url = 'http://' + CONTAINER_IP + '/bWAPP/login.php'
    http_session = http_helper.HTTPSession(login_url)

    http_session.data = 'login=bee&password=bug&security_level=0&form=submit'

    successful_text = 'Welcome Bee'
    http_session.formauth_by_response(successful_text)

    if not http_session.is_auth:
        return {}
    return http_session.cookies


#
# Open tests
#


@pytest.mark.usefixtures('container', 'deploy_bwapp')
def test_owasp_a1_sqli_open():
    """App vulnerable a SQLi?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/sqli_1.php'
    params = {'title': 'a\'', 'action': 'search'}

    expected = 'No movies were found'

    assert http.has_sqli(vulnerable_url, expected, params,
                         cookies=bwapp_cookie)


def test_owasp_a1_os_injection_open():
    """App vulnerable a command injection?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/commandi.php'

    data = {'target': 'www.nsa.gov;uname', 'form': 'submit'}

    expected = 'uname'

    assert http.has_command_injection(vulnerable_url, expected,
                                      data=data, cookies=bwapp_cookie)



def test_owasp_a1_php_injection_open():
    """App vulnerable a PHP injection?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/phpi.php'

    params = {'message': 'test;phpinfo();'}

    expected = '<p><i>test;phpinfo()'

    assert http.has_php_command_injection(vulnerable_url, expected,
                                          params=params,
                                          cookies=bwapp_cookie)


def test_owasp_a2_sessionid_exposed_open():
    """Session ID expuesto?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/smgmt_sessionid_url.php'

    assert http.is_sessionid_exposed(vulnerable_url,
                                     argument='PHPSESSID',
                                     cookies=bwapp_cookie)


@pytest.mark.usefixtures('mock_http')
def test_owasp_a2_session_fixation_open():
    """Session fixation posible?"""
    assert http.has_session_fixation(
        '%s/session_fixation_open' % (BASE_URL), 'Login required')


def test_owasp_a3_xss_open():
    """App vulnerable a XSS?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/xss_get.php'
    params = {'firstname': '<script>alert(1)</script>',
              'lastname': 'b', 'form': 'submit'}

    expected = 'Welcome &lt;script'

    assert http.has_xss(vulnerable_url, expected, params,
                        cookies=bwapp_cookie)


def test_owasp_a4_insecure_dor_open():
    """App vulnerable a direct object reference?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/insecure_direct_object_ref_2.php'

    data = {'ticket_quantity': '1', 'ticket_price': '31337',
            'action': 'order'}

    expected = '<b>15 EUR</b>'

    assert http.has_insecure_dor(vulnerable_url, expected, data=data,
                                 cookies=bwapp_cookie)


def test_owasp_a7_dirtraversal_open():
    """App vulnerable a directory traversal?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/directory_traversal_2.php'

    params = {'directory': '../'}

    expected = 'An error occurred, please try again'

    assert http.has_dirtraversal(vulnerable_url, expected, params=params,
                                 cookies=bwapp_cookie)


def test_owasp_a8_csrf_open():
    """App vulnerable a Cross-Site Request Forgery?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/csrf_1.php'

    params = {'password_new': 'bug', 'password_conf': 'bug',
              'action': 'change'}

    expected = 'Current password'

    assert http.has_csrf(vulnerable_url, expected, params=params,
                         cookies=bwapp_cookie)


#
# Close tests
#


def test_owasp_a1_sqli_close():
    """App vulnerable a SQLi?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/sqli_1.php'
    params = {'title': 'a\'', 'action': 'search'}

    expected = 'No movies were found'
    assert not http.has_sqli(vulnerable_url, expected, params,
                             cookies=bwapp_cookie)


def test_owasp_a1_os_injection_close():
    """App vulnerable a command injection?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/commandi.php'

    data = {'target': 'www.nsa.gov;uname', 'form': 'submit'}

    expected = 'uname'

    assert not http.has_command_injection(vulnerable_url, expected,
                                          data=data,
                                          cookies=bwapp_cookie)


def test_owasp_a1_php_injection_close():
    """App vulnerable a PHP injection?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/phpi.php'

    params = {'message': 'test;phpinfo();'}

    expected = '<p><i>test;phpinfo()'

    assert not http.has_php_command_injection(vulnerable_url, expected,
                                              params=params,
                                              cookies=bwapp_cookie)


def test_owasp_a2_sessionid_exposed_close():
    """Session ID expuesto?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/smgmt_sessionid_url.php'

    assert not http.is_sessionid_exposed(vulnerable_url,
                                         argument='PHPSESSID',
                                         cookies=bwapp_cookie)


@pytest.mark.usefixtures('mock_http')
def test_owasp_a2_session_fixation_close():
    """Session fixation posible?"""
    assert not http.has_session_fixation(
        '%s/session_fixation_close' % (BASE_URL), 'Login required')


def test_owasp_a3_xss_close():
    """App vulnerable a XSS?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/xss_get.php'
    params = {'firstname': '<script>alert(1)</script>',
              'lastname': 'b', 'form': 'submit'}

    expected = 'Welcome &lt;script'

    assert not http.has_xss(vulnerable_url, expected, params,
                            cookies=bwapp_cookie)


def test_owasp_a4_insecure_dor_close():
    """App vulnerable a direct object reference?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/insecure_direct_object_ref_2.php'

    data = {'ticket_quantity': '1', 'ticket_price': '31337',
            'action': 'order'}

    expected = '<b>15 EUR</b>'

    assert not http.has_insecure_dor(vulnerable_url, expected, data=data,
                                     cookies=bwapp_cookie)


def test_owasp_a7_dirtraversal_close():
    """App vulnerable a directory traversal?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/directory_traversal_2.php'

    params = {'directory': '../'}

    expected = 'An error occurred, please try again'

    assert not http.has_dirtraversal(vulnerable_url, expected,
                                     params=params,
                                     cookies=bwapp_cookie)


def test_owasp_a8_csrf_close():
    """App vulnerable a Cross-Site Request Forgery?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/csrf_1.php'

    params = {'password_new': 'bug', 'password_conf': 'bug',
              'action': 'change'}

    expected = 'Current password'

    assert not http.has_csrf(vulnerable_url, expected, params=params,
                             cookies=bwapp_cookie)
