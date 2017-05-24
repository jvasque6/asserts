# -*- coding: utf-8 -*-

"""Modulo para pruebas de HTTP.

Este modulo contiene las funciones necesarias para probar si el modulo de
HTTP se encuentra adecuadamente implementado.
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
def test_a1_sqli_open():
    """App vulnerable a SQLi?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/sqli_1.php'
    params = {'title': 'a\'', 'action': 'search'}

    expected = 'No movies were found'

    assert not http.has_sqli(vulnerable_url, expected, params,
                             cookies=bwapp_cookie)


def test_a1_os_injection_open():
    """App vulnerable a command injection?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/commandi.php'

    data = {'target': 'www.nsa.gov;uname', 'form': 'submit'}

    expected = 'uname'

    assert not http.has_command_injection(vulnerable_url, expected,
                                          data=data, cookies=bwapp_cookie)


def test_a1_php_injection_open():
    """App vulnerable a PHP injection?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/phpi.php'

    params = {'message': 'test;phpinfo();'}

    expected = '<p><i>test;phpinfo()'

    assert not http.has_php_command_injection(vulnerable_url, expected,
                                              params=params,
                                              cookies=bwapp_cookie)


def test_a1_hpp_open():
    """App vulnerable a HTTP Parameter Polluiton?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/hpp-3.php?movie=6&movie=7&movie=8&name=pepe&action=vote'

    expected = 'HTTP Parameter Pollution detected'

    assert not http.has_hpp(vulnerable_url, expected,
                            cookies=bwapp_cookie)


def test_a1_insecure_upload_open():
    """App vulnerable a insecure upload?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/unrestricted_file_upload.php'

    file_param = 'file'
    file_path = 'test/provision/bwapp/exploit.php'
    data = {'MAX_FILE_SIZE': '100000', 'form': 'upload'}

    expected = 'Sorry, the file extension is not allowed'

    assert not http.has_insecure_upload(vulnerable_url, expected,
                                        file_param, file_path, data=data,
                                        cookies=bwapp_cookie)


def test_a2_sessionid_exposed_open():
    """Session ID expuesto?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/smgmt_sessionid_url.php'

    assert http.is_sessionid_exposed(vulnerable_url,
                                     argument='PHPSESSID',
                                     cookies=bwapp_cookie)


@pytest.mark.usefixtures('mock_http')
def test_a2_session_fixation_open():
    """Session fixation posible?"""
    assert not http.has_session_fixation(
        '%s/session_fixation_open' % (BASE_URL), 'Login required')


def test_a3_xss_open():
    """App vulnerable a XSS?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/xss_get.php'
    params = {'firstname': '<script>alert(1)</script>',
              'lastname': 'b', 'form': 'submit'}

    expected = 'Welcome &lt;script'

    assert not http.has_xss(vulnerable_url, expected, params,
                            cookies=bwapp_cookie)


def test_a4_insecure_dor_open():
    """App vulnerable a direct object reference?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/insecure_direct_object_ref_2.php'

    data = {'ticket_quantity': '1', 'ticket_price': '31337',
            'action': 'order'}

    expected = '<b>15 EUR</b>'

    assert not http.has_insecure_dor(vulnerable_url, expected, data=data,
                                     cookies=bwapp_cookie)


def test_a7_dirtraversal_open():
    """App vulnerable a directory traversal?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/directory_traversal_2.php'

    params = {'directory': '../'}

    expected = 'An error occurred, please try again'

    assert not http.has_dirtraversal(vulnerable_url, expected, params=params,
                                     cookies=bwapp_cookie)


def test_a7_lfi_open():
    """App vulnerable a LFI?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/rlfi.php'

    params = {'language': 'message.txt', 'action': 'go'}

    expected = 'Try to climb higher Spidy'

    assert http.has_lfi(vulnerable_url, expected, params=params,
                        cookies=bwapp_cookie)


def test_a8_csrf_open():
    """App vulnerable a Cross-Site Request Forgery?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '0'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/csrf_1.php'

    params = {'password_new': 'bug', 'password_conf': 'bug',
              'action': 'change'}

    expected = 'Current password'

    assert not http.has_csrf(vulnerable_url, expected, params=params,
                             cookies=bwapp_cookie)



@pytest.mark.usefixtures('mock_http')
def test_access_control_allow_origin_open():
    """Header Access-Control-Allow-Origin no establecido?"""
    assert http.is_header_access_control_allow_origin_missing(
        '%s/access_control_allow_origin/fail' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_cache_control_open():
    """Header Cache-Control no establecido?"""
    assert http.is_header_cache_control_missing(
        '%s/cache_control/fail' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_hsts_open():
    """Header Strict-Transport-Security no establecido?"""
    assert http.is_header_hsts_missing(
        '%s/hsts/fail' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_basic_open():
    """Auth BASIC habilitado?"""
    assert http.is_basic_auth_enabled(
        '%s/basic/fail' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_notfound_string_open():
    """Expected string not found?"""
    url = '%s/notfound' % (BASE_URL)
    expected = 'Expected string'
    assert http.has_not_text(url, expected)


@pytest.mark.usefixtures('mock_http')
def test_found_string_open():
    """Expected string not found?"""
    url = '%s/expected' % (BASE_URL)
    expected = 'Expected string'
    assert http.has_text(url, expected)


@pytest.mark.usefixtures('mock_http')
def test_delete_open():
    """HTTP DELETE Allowed"""
    assert http.has_delete_method('%s/delete_open' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_put_open():
    """HTTP PUT Allowed"""
    assert http.has_put_method('%s/put_open' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_trace_open():
    """HTTP TRACE Allowed"""
    assert http.has_trace_method('%s/trace_open' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_version_open():
    """Header Server inseguro?"""
    assert http.is_header_server_insecure(
        '%s/version/fail' % (BASE_URL))


#
# Close tests
#


def test_a1_sqli_close():
    """App vulnerable a SQLi?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/sqli_1.php'
    params = {'title': 'a\'', 'action': 'search'}

    expected = 'No movies were found'
    assert http.has_sqli(vulnerable_url, expected, params,
                         cookies=bwapp_cookie)


def test_a1_os_injection_close():
    """App vulnerable a command injection?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/commandi.php'

    data = {'target': 'www.nsa.gov;uname', 'form': 'submit'}

    expected = 'uname'

    assert http.has_command_injection(vulnerable_url, expected,
                                      data=data,
                                      cookies=bwapp_cookie)


def test_a1_php_injection_close():
    """App vulnerable a PHP injection?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/phpi.php'

    params = {'message': 'test;phpinfo();'}

    expected = '<p><i>test;phpinfo()'

    assert http.has_php_command_injection(vulnerable_url, expected,
                                          params=params,
                                          cookies=bwapp_cookie)


def test_a1_hpp_close():
    """App vulnerable a HTTP Parameter Polluiton?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/hpp-3.php?movie=6&movie=7&movie=8&name=pepe&action=vote'

    expected = 'HTTP Parameter Pollution detected'

    assert http.has_hpp(vulnerable_url, expected, cookies=bwapp_cookie)


def test_a1_insecure_upload_close():
    """App vulnerable a insecure upload?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/unrestricted_file_upload.php'

    file_param = 'file'
    file_path = 'test/provision/bwapp/exploit.php'
    data = {'MAX_FILE_SIZE': '100000', 'form': 'upload'}

    expected = 'Sorry, the file extension is not allowed'

    assert http.has_insecure_upload(vulnerable_url, expected,
                                    file_param, file_path, data=data,
                                    cookies=bwapp_cookie)


def test_a2_sessionid_exposed_close():
    """Session ID expuesto?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/smgmt_sessionid_url.php'

    assert not http.is_sessionid_exposed(vulnerable_url,
                                         argument='PHPSESSID',
                                         cookies=bwapp_cookie)


@pytest.mark.usefixtures('mock_http')
def test_a2_session_fixation_close():
    """Session fixation posible?"""
    assert http.has_session_fixation(
        '%s/session_fixation_close' % (BASE_URL), 'Login required')


def test_a3_xss_close():
    """App vulnerable a XSS?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/xss_get.php'
    params = {'firstname': '<script>alert(1)</script>',
              'lastname': 'b', 'form': 'submit'}

    expected = 'Welcome &lt;script'

    assert http.has_xss(vulnerable_url, expected, params,
                        cookies=bwapp_cookie)


def test_a4_insecure_dor_close():
    """App vulnerable a direct object reference?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/insecure_direct_object_ref_2.php'

    data = {'ticket_quantity': '1', 'ticket_price': '31337',
            'action': 'order'}

    expected = '<b>15 EUR</b>'

    assert http.has_insecure_dor(vulnerable_url, expected, data=data,
                                 cookies=bwapp_cookie)


def test_a7_dirtraversal_close():
    """App vulnerable a directory traversal?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/directory_traversal_2.php'

    params = {'directory': '../'}

    expected = 'An error occurred, please try again'

    assert http.has_dirtraversal(vulnerable_url, expected,
                                 params=params,
                                 cookies=bwapp_cookie)


def test_a7_lfi_close():
    """App vulnerable a LFI?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/rlfi.php'

    params = {'language': 'message.txt', 'action': 'go'}

    expected = 'Try to climb higher Spidy'

    assert not http.has_lfi(vulnerable_url, expected, params=params,
                            cookies=bwapp_cookie)


def test_a8_csrf_close():
    """App vulnerable a Cross-Site Request Forgery?"""
    bwapp_cookie = get_bwapp_cookies()
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + CONTAINER_IP + \
        '/bWAPP/csrf_1.php'

    params = {'password_new': 'bug', 'password_conf': 'bug',
              'action': 'change'}

    expected = 'Current password'

    assert http.has_csrf(vulnerable_url, expected, params=params,
                         cookies=bwapp_cookie)


@pytest.mark.usefixtures('mock_http')
def test_access_control_allow_origin_close():
    """Header Access-Control-Allow-Origin establecido?"""
    assert not http.is_header_access_control_allow_origin_missing(
        '%s/access_control_allow_origin/ok' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_cache_control_close():
    """Header Cache-Control establecido?"""
    assert not http.is_header_cache_control_missing(
        '%s/cache_control/ok' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_hsts_close():
    """Header Strict-Transport-Security establecido?"""
    assert not http.is_header_hsts_missing(
        '%s/hsts/ok' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_basic_close():
    """Auth BASIC no habilitado?"""
    assert not http.is_basic_auth_enabled(
        '%s/basic/ok' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_put_close():
    """HTTP PUT Not Allowed"""
    assert not http.has_put_method('%s/put_close' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_trace_close():
    """HTTP TRACE Not Allowed"""
    assert not http.has_trace_method('%s/trace_close' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_delete_close():
    """HTTP DELETE Not Allowed"""
    assert not http.has_delete_method('%s/delete_close' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_notfound_string_close():
    """Expected string not found?"""
    url = '%s/notfound' % (BASE_URL)
    expected = 'Expected string'
    assert not http.has_text(url, expected)


@pytest.mark.usefixtures('mock_http')
def test_found_string_close():
    """Expected string not found?"""
    url = '%s/expected' % (BASE_URL)
    expected = 'Expected string'
    assert not http.has_not_text(url, expected)


@pytest.mark.usefixtures('mock_http')
def test_version_close():
    """Header Server inseguro?"""
    assert not http.is_header_server_insecure(
        '%s/version/ok' % (BASE_URL))


#
# TODO(glopez) Functions in HTTP library
#
# http.has_header_x_xxs_protection('%s/access_control_allow_origin/fail'
#   % (BASE_URL))
# http.has_header_x_xxs_protection("http://challengeland.co/")
# http.has_header_x_frame_options("http://localhost/cursos")
# http.has_header_x_frame_options("http://challengeland.co/")
# http.has_header_x_permitted_cross_domain_policies("http://localhost/cursos")
# http.has_header_x_permitted_cross_domain_policies("http://challengeland.co/")
# http.has_header_x_content_type_options("http://localhost/cursos")
# http.has_header_x_content_type_options("http://challengeland.co")
# http.has_header_pragma("http://localhost/cursos")
# http.has_header_pragma("http://challengeland.co")
# http.has_header_expires("http://localhost/cursos")
# http.has_header_expires("http://challengeland.co")
# http.has_header_pragma("http://localhost/cursos")
# http.has_header_content_type("http://challengeland.co")
# http.has_header_content_security_policy("http://challengeland.co")
# http.has_header_content_security_policy("http://localhost/cursos")
# cookie.has_http_only("http://challengeland.co","ci_session")
# http.basic_auth("http://localhost/fluidopens/BasicAuth/","root","1234")
# http.basic_auth("http://localhost/fluidopens/BasicAuth/","Admin","1234")
# Asymetric testing
# http.response_is_stable(seconds, URL, repeat)
