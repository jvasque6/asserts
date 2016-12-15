# -*- coding: utf-8 -*-

"""Modulo de ayuda HTTP
"""

# standard imports
import logging
import re
from functools import wraps
import requests


# 3rd party imports
from bs4 import BeautifulSoup

# local imports
# none


class HTTPRequest(object):
    """Class of HTTP request objects."""

    def __init__(self, url, params=None, headers=dict(),
                 cookies=None, data='', auth=None):
        self.url = url
        self.params = params
        self.headers = headers
        self.cookies = cookies
        self.data = data
        self.auth = auth
        self.headers['user-agent'] = 'Mozilla/5.0 \
            (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)'

    def do_request(self):
        """Realiza una petición HTTP."""
        try:
            if self.data == '':
                return requests.get(self.url, verify=False,
                                    auth=self.auth,
                                    params=self.params,
                                    cookies=self.cookies,
                                    headers=self.headers)
            else:
                return requests.post(url, verify=False,
                                     data=self.data,
                                     auth=self.auth,
                                     params=self.params,
                                     cookies=self.cookies,
                                     headers=self.headers)
        except requests.ConnectionError:
            logging.error('Sin acceso a %s , %s', self.url, 'ERROR')

    def formauth_by_statuscode(self, code):
        """Autentica y verifica autenticacion usando codigo HTTP."""
        http_req = self.do_request()

        if http_req.status_code == code:
            logging.info('POST Authentication %s, Details=%s, %s',
                         self.url, 'Success with ' + str(self.data),
                         'OPEN')
        else:
            logging.info('POST Authentication %s, Details=%s, %s',
                         self.url,
                         'Error code (' + str(http_req.status_code) +
                         ') ' + str(self.data),
                         'CLOSE')
        return http_req

    def formauth_by_response(self, text):
        """Autentica y verifica autenticacion usando regex."""
        http_req = self.do_request()

        if http_req.text.find(text) >= 0:
            logging.info('POST Authentication %s, Details=%s, %s',
                         self.url, 'Success with ' + str(self.data),
                         'OPEN')
        else:
            logging.info(
                'POST Authentication %s, Details=%s, %s',
                self.url,
                'Error text (' + http_req.text + ') ' + str(self.data),
                'CLOSE')
        return http_req

    def basic_auth(self, user, passw):
        """Autentica usando BASIC HTTP."""
        self.auth = (user, passw)
        resp = self.do_request()

        self.auth = None
        request_no_auth = self.do_request(url)
        if request_no_auth.status_code == 401:
            if resp.status_code == 200:
                logging.info(
                    'HTTPBasicAuth %s, Details=%s, %s',
                    self.url,
                    'Success with [ ' + user + ' : ' + passw + ' ]',
                    'OPEN')
            else:
                logging.info('HTTPBasicAuth %s, Details=%s, %s',
                             self.url,
                             'Fail with [ ' + user + ' : ' + passw + ' ]',
                             'CLOSE')
        else:
            logging.info('HTTPBasicAuth %s, Details=%s, %s', self.url,
                         'HTTPBasicAuth Not present', 'CLOSE')

    def oauth_auth(self, user, passw):
        """XXXXXXXXXXXXXX."""
        self.auth = OAuth1(user, passw)
        resp = do_request()

        self.auth = None
        request_no_auth = do_request()
        if request_no_auth.status_code == 401:
            if resp.status_code == 200:
                logging.info(
                    'HTTPOAuth %s, Details=%s, %s',
                    self.url,
                    'Success with [ ' + user + ' : ' + passw + ' ]',
                    'OPEN')
            else:
                logging.info('HTTPOAuth %s, Details=%s, %s', self.url,
                             'Fail with [ ' + user + ' : ' + passw + ' ]',
                             'CLOSE')
        else:
            logging.info('HTTPOAuth %s, Details=%s, %s', self.url,
                         'HTTPOAuth Not present', 'CLOSE')


def find_value_in_response(raw_text, field_type, field_name):
    soup = BeautifulSoup(raw_text, "lxml")
    for tag in soup(field_type):
        if tag.get('name') == field_name:
            return tag.get('value')


def generic_http_assert(url, expected_regex, headers={},
                        cookies=None, params=None, data=''):
    """Generic HTTP assert method."""
    request = HTTPRequest(url=url, headers=headers, params=params,
                           cookies=cookies, data=data)
    response = request.do_request()
    the_page = response.text

    if re.search(str(expected_regex), the_page) is None:
        logging.info('%s HTTP assertion not found, Details=%s, %s',
                     url, expected_regex, 'OPEN')
        return True
    else:
        logging.info('%s HTTP assertion succeed, Details=%s, %s',
                     url, expected_regex, 'CLOSE')
        return False


def dvwa_vuln(vuln, host, level='hard'):
    """Application decorator factory."""
    def my_decorator(func):
        """Decorator."""
        if vuln == 'SQLi':
            @wraps(func)
            def sqli(**kargs):
                """Establece las variables para probar SQLi en DVWA."""
                url = 'http://' + host + '/dvwa/vulnerabilities/sqli/'
                params = {'id': 'a\'', 'Submit': 'Submit'}
                expected_regex = 'html'

                if level == 'hard':
                    security_level = 'impossible'
                else:
                    security_level = 'low'
                cookies = {'security': security_level}

                kwargs = {'url': url, 'params': params,
                          'expected_regex': expected_regex,
                          'cookies': cookies}
                func(**kwargs)
            return sqli
        if vuln == 'XSS':
            @wraps(func)
            def xss(**kargs):
                """Establece las variables para probar XSS en DVWA."""
                pass
            return xss
    return my_decorator


def http_app(app, host):
    """Application decorator factory."""
    def my_decorator(func):
        """Decorator."""
        if app == 'DVWA':
            @wraps(func)
            def do_dvwa(**kargs):
                """Ejecuta acciones necesarias para loguearse en DVWA."""
                url = 'http://' + host + '/dvwa/login.php'

                request1 = HTTPRequest(url)
                response = request1.do_request()

                sessionid = response.cookies.get_dict()['PHPSESSID']
                cookies = {'security': 'low', 'PHPSESSID': sessionid}

                csrf_token = find_value_in_response(response.text,
                                                    'input',
                                                    'user_token')

                headers = {'Content-Type': 'application/x-www-form-urlencoded',
                           'Accept': '*/*'}
                data = 'username=admin&password=password&user_token=' + \
                    csrf_token + '&Login=Login'

                request2 = HTTPRequest(url, headers=headers,
                                       cookies=cookies, data=data)

                successful_text = 'Welcome to Damn Vulnerable'
                request2.formauth_by_response(successful_text)

                url = kargs['url']
                params = kargs['params']
                cookies['security'] = kargs['cookies']['security']
                expected_regex = kargs['expected_regex']

                kwargs = {'url': url, 'params': params,
                          'expected_regex': expected_regex,
                          'headers': headers,
                          'cookies': cookies}
                func(**kwargs)
            return do_dvwa
    return my_decorator
