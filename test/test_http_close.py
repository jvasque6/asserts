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
from fluidasserts.proto import http
import fluidasserts.utils.decorators

#
# Constants
#
fluidasserts.utils.decorators.UNITTEST = True
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


def get_bwapp_cookies(cont_ip):
    """Log in to bWAPP and return valid cookie."""
    install_url = 'http://' + cont_ip + '/install.php?install=yes'
    http_helper.HTTPSession(install_url)
    login_url = 'http://' + cont_ip + '/login.php'
    http_session = http_helper.HTTPSession(login_url)

    http_session.data = 'login=bee&password=bug&security_level=0&form=submit'

    successful_text = 'Welcome Bee'
    http_session.formauth_by_response(successful_text)

    if not http_session.is_auth:
        return {}
    return http_session.cookies

#
# Close tests
#


@pytest.mark.parametrize('run_mock',
                         [('bwapp', {'80/tcp': BWAPP_PORT})],
                         indirect=True)
def test_a1_sqli_close(run_mock):
    """App vulnerable a SQLi?."""
    bwapp_cookie = get_bwapp_cookies(run_mock)
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + run_mock + '/sqli_1.php'
    params = {'title': 'a\'', 'action': 'search'}

    assert not http.has_sqli(vulnerable_url, params, cookies=bwapp_cookie)


def test_a1_os_injection_close(run_mock):
    """App vulnerable a command injection?."""
    bwapp_cookie = get_bwapp_cookies(run_mock)
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + run_mock + '/commandi.php'

    data = {'target': 'www.nsa.gov;uname', 'form': 'submit'}

    expected = 'uname'

    assert not http.has_command_injection(vulnerable_url, expected,
                                          data=data,
                                          cookies=bwapp_cookie)


def test_a1_php_injection_close(run_mock):
    """App vulnerable a PHP injection?."""
    bwapp_cookie = get_bwapp_cookies(run_mock)
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + run_mock + '/phpi.php'

    params = {'message': 'test;phpinfo();'}

    expected = '<p><i>test;phpinfo()'

    assert http.has_php_command_injection(vulnerable_url, expected,
                                          params=params,
                                          cookies=bwapp_cookie)


def test_a1_hpp_close(run_mock):
    """App vulnerable a HTTP Parameter Polluiton?."""
    bwapp_cookie = get_bwapp_cookies(run_mock)
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + run_mock + \
        '/hpp-3.php?movie=6&movie=7&movie=8&name=pepe&action=vote'

    expected = 'HTTP Parameter Pollution detected'

    assert http.has_hpp(vulnerable_url, expected, cookies=bwapp_cookie)


def test_a1_insecure_upload_close(run_mock):
    """App vulnerable a insecure upload?."""
    bwapp_cookie = get_bwapp_cookies(run_mock)
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + run_mock + '/unrestricted_file_upload.php'

    file_param = 'file'
    file_path = 'test/provision/bwapp/exploit.php'
    data = {'MAX_FILE_SIZE': '100000', 'form': 'upload'}

    expected = 'Sorry, the file extension is not allowed'

    assert http.has_insecure_upload(vulnerable_url, expected,
                                    file_param, file_path, data=data,
                                    cookies=bwapp_cookie)


def test_a2_sessionid_exposed_close(run_mock):
    """Session ID expuesto?."""
    bwapp_cookie = get_bwapp_cookies(run_mock)
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + run_mock + '/smgmt_sessionid_url.php'

    assert not http.is_sessionid_exposed(vulnerable_url,
                                         argument='PHPSESSID',
                                         cookies=bwapp_cookie)


@pytest.mark.usefixtures('mock_http')
def test_a2_session_fixation_close():
    """Session fixation posible?."""
    assert http.has_session_fixation(
        '%s/session_fixation_close' % (BASE_URL), 'Login required')


def test_a3_xss_close(run_mock):
    """App vulnerable a XSS?."""
    bwapp_cookie = get_bwapp_cookies(run_mock)
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + run_mock + \
        '/xss_get.php'
    params = {'firstname': '<script>alert(1)</script>',
              'lastname': 'b', 'form': 'submit'}

    expected = 'Welcome &lt;script'

    assert http.has_xss(vulnerable_url, expected, params,
                        cookies=bwapp_cookie)


def test_a4_insecure_dor_close(run_mock):
    """App vulnerable a direct object reference?."""
    bwapp_cookie = get_bwapp_cookies(run_mock)
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + run_mock + '/insecure_direct_object_ref_2.php'

    data = {'ticket_quantity': '1', 'ticket_price': '31337',
            'action': 'order'}

    expected = '<b>15 EUR</b>'

    assert http.has_insecure_dor(vulnerable_url, expected, data=data,
                                 cookies=bwapp_cookie)


def test_a7_dirtraversal_close(run_mock):
    """App vulnerable a directory traversal?."""
    bwapp_cookie = get_bwapp_cookies(run_mock)
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + run_mock + '/directory_traversal_2.php'

    params = {'directory': '../'}

    expected = 'An error occurred, please try again'

    assert http.has_dirtraversal(vulnerable_url, expected,
                                 params=params,
                                 cookies=bwapp_cookie)


def test_a7_lfi_close(run_mock):
    """App vulnerable a LFI?."""
    bwapp_cookie = get_bwapp_cookies(run_mock)
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + run_mock + '/rlfi.php'

    params = {'language': 'message.txt', 'action': 'go'}

    expected = 'Try to climb higher Spidy'

    assert not http.has_lfi(vulnerable_url, expected, params=params,
                            cookies=bwapp_cookie)


def test_a8_csrf_close(run_mock):
    """App vulnerable a Cross-Site Request Forgery?."""
    bwapp_cookie = get_bwapp_cookies(run_mock)
    bwapp_cookie['security_level'] = '2'

    vulnerable_url = 'http://' + run_mock + '/csrf_1.php'

    params = {'password_new': 'bug', 'password_conf': 'bug',
              'action': 'change'}

    expected = 'Current password'

    assert http.has_csrf(vulnerable_url, expected, params=params,
                         cookies=bwapp_cookie)


@pytest.mark.usefixtures('mock_http')
def test_access_control_allow_origin_close():
    """Header Access-Control-Allow-Origin establecido?."""
    assert not http.is_header_access_control_allow_origin_missing(
        '%s/access_control_allow_origin/ok' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_cache_control_close():
    """Header Cache-Control establecido?."""
    assert not http.is_header_cache_control_missing(
        '%s/cache_control/ok' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_hsts_close():
    """Header Strict-Transport-Security establecido?."""
    assert not http.is_header_hsts_missing(
        '%s/hsts/ok' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_basic_close():
    """Auth BASIC no habilitado?."""
    assert not http.is_basic_auth_enabled(
        '%s/basic/ok' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_put_close():
    """HTTP PUT Not Allowed."""
    assert not http.has_put_method('%s/put_close' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_trace_close():
    """HTTP TRACE Not Allowed."""
    assert not http.has_trace_method('%s/trace_close' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_delete_close():
    """HTTP DELETE Not Allowed."""
    assert not http.has_delete_method('%s/delete_close' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_notfound_string_close():
    """Expected string not found?."""
    url = '%s/notfound' % (BASE_URL)
    expected = 'Expected string'
    assert not http.has_text(url, expected)


@pytest.mark.usefixtures('mock_http')
def test_found_string_close():
    """Expected string not found?."""
    url = '%s/expected' % (BASE_URL)
    expected = 'Expected string'
    assert not http.has_not_text(url, expected)


@pytest.mark.usefixtures('mock_http')
def test_userenum_post_close():
    """Enumeracion de usuarios posible?."""
    data = 'username=pepe&password=grillo'
    assert not http.has_user_enumeration(
        '%s/userenum_post/ok' % (MOCK_SERVICE),
        'username', data=data)


@pytest.mark.usefixtures('mock_http')
def test_userenum_get_close():
    """Enumeracion de usuarios posible?."""
    data = 'username=pepe&password=grillo'
    assert not http.has_user_enumeration(
        '%s/userenum_get/ok' % (MOCK_SERVICE),
        'username', params=data)


@pytest.mark.usefixtures('mock_http')
def test_bruteforce_close():
    """Bruteforce posible?."""
    data = 'username=pepe&password=grillo'
    assert not http.can_brute_force(
        '%s/bruteforce/ok' % (MOCK_SERVICE),
        'admin',
        'username',
        'password',
        user_list=['root', 'admin'],
        pass_list=['pass', 'password'],
        data=data)
    assert not http.can_brute_force(
        '%s/bruteforce/ok' % (MOCK_SERVICE),
        'admin',
        'username',
        'password',
        user_list=['root', 'admin'],
        pass_list=['pass', 'password'],
        data=data,
        params='')


@pytest.mark.usefixtures('mock_http')
def test_responsetime_close():
    """Tiempo de respuesta aceptable?."""
    assert not http.is_response_delayed(
        '%s/responsetime/ok' % (MOCK_SERVICE))


@pytest.mark.usefixtures('mock_http')
def test_dirlisting_close():
    """Dirlisting habilitado?."""
    assert not http.has_dirlisting(
        '%s/dirlisting/ok' % (MOCK_SERVICE))


@pytest.mark.usefixtures('mock_http')
def test_http_response_close():
    """Respuesta 403 FORBIDDEN?."""
    assert not http.is_resource_accessible(
        '%s/reponse/ok' % (MOCK_SERVICE))


@pytest.mark.usefixtures('mock_http')
def test_is_header_x_asp_net_version_present_close():
    """Header X-AspNet-Version establecido?."""
    assert not http.is_header_x_asp_net_version_present(
        '%s/x_aspnet_version/ok' % (BASE_URL))


# @pytest.mark.usefixtures('mock_http')
# def test_is_version_visible_close():
#    assert not http.is_version_visible('127.0.0.1', port=5000)


@pytest.mark.usefixtures('mock_http')
def test_is_header_x_xxs_protection_missing_close():
    """Header x-xss-protection establecido?."""
    assert not http.is_header_x_xxs_protection_missing(
        '%s/xxs_protection/ok' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_is_header_perm_cross_dom_pol_missing_close():
    """Header cross-domain-policy establecido?."""
    assert not http.is_header_perm_cross_dom_pol_missing(
        '%s/perm_cross_dom_pol/ok' % (BASE_URL))


@pytest.mark.usefixtures('mock_http')
def test_has_clear_viewstate_close():
    """ViewState cifrado?."""
    assert not http.has_clear_viewstate(
        '%s/http/viewstate/encrypted/ok' % (MOCK_SERVICE))

    assert not http.has_clear_viewstate(
        '%s/http/viewstate/encrypted/not_found' % (MOCK_SERVICE))
