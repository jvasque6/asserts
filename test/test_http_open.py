# -*- coding: utf-8 -*-

"""Modulo para pruebas de HTTP.

Este modulo contiene las funciones necesarias para probar si el modulo de
HTTP se encuentra adecuadamente implementado.
"""

# standard imports
from __future__ import print_function
from multiprocessing import Process
import time

# 3rd party imports
from test.mock import httpserver
import pytest

# local imports
from fluidasserts.helper import http_helper
from fluidasserts.service import http
import fluidasserts.utils.decorators

#
# Constants
#
fluidasserts.utils.decorators.UNITTEST = True
CONTAINER_IP = '172.30.216.101'
MOCK_SERVICE = 'http://localhost:5000'
BASE_URL = MOCK_SERVICE + '/http/headers'
BWAPP_PORT = 80

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
    time.sleep(0.5)

    def teardown():
        """Detiene servidor HTTP al finalizar las pruebas."""
        prcs.terminate()

    request.addfinalizer(teardown)


def get_bwapp_cookies():
    """Log in to bWAPP and return valid cookie."""
    install_url = 'http://' + CONTAINER_IP + '/install.php?install=yes'
    http_helper.HTTPSession(install_url)
    login_url = 'http://' + CONTAINER_IP + '/login.php'
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


@pytest.mark.parametrize('run_mock',
                         [('bwapp', {'80/tcp': BWAPP_PORT})],
                         indirect=True)
# pylint: disable=unused-argument
def test_a1_sqli_open(run_mock):
    """App vulnerable a SQLi?."""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'
    vulnerable_url = 'http://' + CONTAINER_IP + '/sqli_1.php'
    params = {'title': 'a\'', 'action': 'search'}
    assert http.has_sqli(vulnerable_url, params, cookies=bwapp_cookie)


# pylint: disable=unused-argument
def test_a1_os_injection_open(run_mock):
    """App vulnerable a command injection?."""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/commandi.php'

    data = {'target': 'www.nsa.gov;uname', 'form': 'submit'}

    expected = 'uname'

    assert not http.has_command_injection(vulnerable_url, expected,
                                          data=data, cookies=bwapp_cookie)


# pylint: disable=unused-argument
def test_a1_php_injection_open(run_mock):
    """App vulnerable a PHP injection?."""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/phpi.php'

    params = {'message': 'test;phpinfo();'}

    expected = '<p><i>test;phpinfo()'

    assert not http.has_php_command_injection(vulnerable_url, expected,
                                              params=params,
                                              cookies=bwapp_cookie)


# pylint: disable=unused-argument
def test_a1_hpp_open(run_mock):
    """App vulnerable a HTTP Parameter Polluiton?."""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/hpp-3.php?movie=6&movie=7&movie=8&name=pepe&action=vote'

    expected = 'HTTP Parameter Pollution detected'

    assert not http.has_hpp(vulnerable_url, expected,
                            cookies=bwapp_cookie)


# pylint: disable=unused-argument
def test_a1_insecure_upload_open(run_mock):
    """App vulnerable a insecure upload?."""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/unrestricted_file_upload.php'

    file_param = 'file'
    file_path = 'test/provision/bwapp/exploit.php'
    data = {'MAX_FILE_SIZE': '100000', 'form': 'upload'}

    expected = 'Sorry, the file extension is not allowed'

    assert not http.has_insecure_upload(vulnerable_url, expected,
                                        file_param, file_path, data=data,
                                        cookies=bwapp_cookie)


# pylint: disable=unused-argument
def test_a2_sessionid_exposed_open(run_mock):
    """Session ID expuesto?."""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie.set('security_level', '0', domain=CONTAINER_IP, path='/')

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/smgmt_sessionid_url.php'

    assert http.is_sessionid_exposed(vulnerable_url,
                                     argument='PHPSESSID',
                                     cookies=bwapp_cookie)


@pytest.mark.usefixtures('mock_http')
def test_a2_session_fixation_open():
    """Session fixation posible?."""
    assert not http.has_session_fixation(
        '%s/session_fixation_open' % (BASE_URL), 'Login required')


# pylint: disable=unused-argument
def test_a3_xss_open(run_mock):
    """App vulnerable a XSS?."""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/xss_get.php'
    params = {'firstname': '<script>alert(1)</script>',
              'lastname': 'b', 'form': 'submit'}

    expected = 'Welcome &lt;script'

    assert not http.has_xss(vulnerable_url, expected, params,
                            cookies=bwapp_cookie)


# pylint: disable=unused-argument
def test_a4_insecure_dor_open(run_mock):
    """App vulnerable a direct object reference?."""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/insecure_direct_object_ref_2.php'

    data = {'ticket_quantity': '1', 'ticket_price': '31337',
            'action': 'order'}

    expected = '<b>15 EUR</b>'

    assert not http.has_insecure_dor(vulnerable_url, expected, data=data,
                                     cookies=bwapp_cookie)


# pylint: disable=unused-argument
def test_a7_dirtraversal_open(run_mock):
    """App vulnerable a directory traversal?."""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/directory_traversal_2.php'

    params = {'directory': '../'}

    expected = 'An error occurred, please try again'

    assert not http.has_dirtraversal(vulnerable_url, expected, params=params,
                                     cookies=bwapp_cookie)


# pylint: disable=unused-argument
def test_a7_lfi_open(run_mock):
    """App vulnerable a LFI?."""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/rlfi.php'

    params = {'language': 'message.txt', 'action': 'go'}

    expected = 'Try to climb higher Spidy'

    assert http.has_lfi(vulnerable_url, expected, params=params,
                        cookies=bwapp_cookie)


# pylint: disable=unused-argument
def test_a8_csrf_open(run_mock):
    """App vulnerable a Cross-Site Request Forgery?."""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/csrf_1.php'

    params = {'password_new': 'bug', 'password_conf': 'bug',
              'action': 'change'}

    expected = 'Current password'

    assert not http.has_csrf(vulnerable_url, expected, params=params,
                             cookies=bwapp_cookie)


@pytest.mark.usefixtures('mock_http')
def test_access_control_allow_origin_open():
    """Header Access-Control-Allow-Origin no establecido?."""
    assert http.is_header_access_control_allow_origin_missing(
        '%s/access_control_allow_origin/fail' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_cache_control_open():
    """Header Cache-Control no establecido?."""
    assert http.is_header_cache_control_missing(
        '%s/cache_control/fail' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_hsts_open():
    """Header Strict-Transport-Security no establecido?."""
    assert http.is_header_hsts_missing(
        '%s/hsts/fail' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_basic_open():
    """Auth BASIC habilitado?."""
    assert http.is_basic_auth_enabled(
        '%s/basic/fail' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_notfound_string_open():
    """Expected string not found?."""
    url = '%s/notfound' % (BASE_URL)
    expected = 'Expected string'
    assert http.has_not_text(url, expected)


@pytest.mark.usefixtures('mock_http')
def test_found_string_open():
    """Expected string not found?."""
    url = '%s/expected' % (BASE_URL)
    expected = 'Expected string'
    assert http.has_text(url, expected)


@pytest.mark.usefixtures('mock_http')
def test_delete_open():
    """HTTP DELETE Allowed."""
    assert http.has_delete_method('%s/delete_open' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_put_open():
    """HTTP PUT Allowed."""
    assert http.has_put_method('%s/put_open' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_trace_open():
    """HTTP TRACE Allowed."""
    assert http.has_trace_method('%s/trace_open' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_version_open():
    """Header Server inseguro?."""
    assert http.is_header_server_present(
        '%s/version/fail' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_userenum_post_open():
    """Enumeracion de usuarios posible?."""
    data = 'username=pepe&password=grillo'
    assert http.has_user_enumeration(
        '%s/userenum_post/fail' % (MOCK_SERVICE),
        'username', data=data)


@pytest.mark.usefixtures('mock_http')
def test_userenum_get_open():
    """Enumeracion de usuarios posible?."""
    data = 'username=pepe&password=grillo'
    assert http.has_user_enumeration(
        '%s/userenum_get/fail' % (MOCK_SERVICE),
        'username', params=data)


@pytest.mark.usefixtures('mock_http')
def test_bruteforce_open():
    """Bruteforce posible?."""
    data = 'username=pepe&password=grillo'
    assert http.can_brute_force(
        '%s/bruteforce/fail' % (MOCK_SERVICE),
        'admin',
        'username',
        'password',
        user_list=['root', 'admin'],
        pass_list=['pass', 'password'],
        data=data)


@pytest.mark.usefixtures('mock_http')
def test_responsetime_open():
    """Tiempo de respuesta aceptable?."""
    assert http.is_response_delayed(
        '%s/responsetime/fail' % (MOCK_SERVICE))


@pytest.mark.usefixtures('mock_http')
def test_dirlisting_open():
    """Dirlisting habilitado?."""
    assert http.has_dirlisting(
        '%s/dirlisting/fail' % (MOCK_SERVICE))


@pytest.mark.usefixtures('mock_http')
def test_http_response_open():
    """Respuesta 201 CREATED?."""
    assert http.is_resource_accessible(
        '%s/reponse/fail' % (MOCK_SERVICE))
