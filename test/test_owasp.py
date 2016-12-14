# -*- coding: utf-8 -*-

"""Modulo para pruebas de OWASP TOP 10.

Este modulo contiene las funciones necesarias
para probar OWASP TOP 10 2013 de aplicaciones.
"""

# standard imports
import subprocess

# 3rd party imports
import pytest
from bs4 import BeautifulSoup

# local imports
from fluidasserts.helper import http_helper

#
# Constants
#

# None

#
# Fixtures
#


@pytest.fixture(scope='module')
def deploy_dvwa():
    """Despliega DVWA."""
    print('Deploying Damn Vulnerable Web Application')
    subprocess.call('ansible-playbook test/provision/dvwa.yml',
                    shell=True)

# Open tests
#


CONTAINER_IP = '172.30.216.100'


@pytest.mark.usefixtures('container', 'deploy_dvwa')
def test_sqli_open():
    """SQL injection habilitado?"""
    url = 'http://' + CONTAINER_IP + '/dvwa/login.php'

    request1 = http_helper.HTTPRequest(url)
    response = request1.do_request()

    sessionid = response.cookies.get_dict()['PHPSESSID']
    cookie = {'security': 'low', 'PHPSESSID': sessionid}

    soup = BeautifulSoup(response.text, "lxml")
    for tag in soup("input"):
        if tag.get('name') == 'user_token':
            csrf_token = tag.get('value')

    headers = {'Content-Type': 'application/x-www-form-urlencoded',
               'Accept': '*/*'}
    data = 'username=admin&password=password&user_token=' + \
        csrf_token + '&Login=Login'

    request2 = http_helper.HTTPRequest(url, headers=headers,
                                       cookies=cookie, data=data)
    response = request2.do_request()

    url = 'http://' + CONTAINER_IP + '/dvwa/vulnerabilities/sqli/'
    params = {'id': 'a\'', 'Submit': 'Submit'}
    expected_regex = 'main_body'
    failure_regex = 'You have an error in your SQL syntax'

    assert http_helper.generic_http_assert(url, expected_regex,
                                           failure_regex,
                                           headers, cookies=cookie,
                                           params=params)

#
# Close tests
#


def test_sqli_close():
    """SQL injection habilitado?"""
    url = 'http://' + CONTAINER_IP + '/dvwa/login.php'

    request1 = http_helper.HTTPRequest(url)
    response = request1.do_request()

    sessionid = response.cookies.get_dict()['PHPSESSID']
    cookie = {'security': 'impossible', 'PHPSESSID': sessionid}

    soup = BeautifulSoup(response.text, "lxml")
    for tag in soup("input"):
        if tag.get('name') == 'user_token':
            csrf_token = tag.get('value')

    headers = {'Content-Type': 'application/x-www-form-urlencoded',
               'Accept': '*/*'}
    data = 'username=admin&password=password&user_token=' + \
        csrf_token + '&Login=Login'

    request2 = http_helper.HTTPRequest(url, headers=headers,
                                       cookies=cookie, data=data)
    response = request2.do_request()

    url = 'http://' + CONTAINER_IP + '/dvwa/vulnerabilities/sqli/'
    params = {'id': 'a\'', 'Submit': 'Submit'}
    expected_regex = 'main_body'
    failure_regex = 'You have an error in your SQL syntax'

    assert not http_helper.generic_http_assert(url, expected_regex,
                                               failure_regex,
                                               headers, cookies=cookie,
                                               params=params)
