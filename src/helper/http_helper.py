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
    """Clase de objetos HTTP requests."""

    def __init__(self, url, params=None, headers=dict(),
                 cookies=None, data='', auth=None):
        self.url = url
        self.params = params
        self.headers = headers
        self.cookies = cookies
        self.data = data
        self.auth = auth
        self.headers['user-agent'] = \
            'Mozilla/5.0 (X11; Linux x86_64) \
            AppleWebKit/537.36 (KHTML, like Gecko)'

    def do_request(self):
        """Realiza una petición HTTP."""
        try:
            if self.data == '':
                return requests.get(self.url, verify=False,
                                    auth=self.auth, params=self.params,
                                    cookies=self.cookies,
                                    headers=self.headers)
            else:
                return requests.post(self.url, verify=False,
                                     data=self.data, auth=self.auth,
                                     params=self.params,
                                     cookies=self.cookies,
                                     headers=self.headers)
        except requests.ConnectionError:
            logging.error('Sin acceso a %s , %s', self.url, 'ERROR')


def generic_http_assert(url, expected_regex, failure_regex,
                        headers={}, cookies=None, params=None, data=''):
    """Generic HTTP assert method."""
    request = HTTPRequest(url=url, headers=headers, params=params,
                          cookies=cookies, data=data)

    response = request.do_request()

    the_page = response.text

    if re.search(str(failure_regex), the_page):
        logging.info('%s HTTP assertion failed, Details=%s, %s',
                     url, failure_regex, 'OPEN')
        return True
    elif re.search(str(expected_regex), the_page) is None:
        logging.info('%s HTTP assertion not found, Details=%s, %s',
                     url, expected_regex, 'OPEN')
        return True
    elif re.search(str(expected_regex), the_page):
        logging.info('%s HTTP assertion succeed, Details=%s, %s',
                     url, expected_regex, 'CLOSE')
        return False


def sqli_engine(engine):
    """SQL engine decorator factory."""
    def my_decorator(func):
        """Decorator."""
        @wraps(func)
        def sql_engine_wrapper():
            """Wrapper function."""
            expected_regex = 'html'
            if engine == 'MySQL':
                failure_regex = 'You have an error in your SQL syntax'
            elif engine == 'MSSQL':
                failure_regex = 'Microsoft OLE DB Provider for ODBC'
            else:
                failure_regex = 'You have an error in your SQL syntax'

            kwargs = {'expected_regex': expected_regex,
                      'failure_regex': failure_regex}
            return func(**kwargs)
        return sql_engine_wrapper
    return my_decorator


def sqli_app(app, host, level='hard'):
    """SQL injection application decorator factory."""
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
                if level == 'hard':
                    security_level = 'impossible'
                else:
                    security_level = 'low'
                cookie = {'security': security_level, 'PHPSESSID': sessionid}

                soup = BeautifulSoup(response.text, "lxml")
                for tag in soup('input'):
                    if tag.get('name') == 'user_token':
                        csrf_token = tag.get('value')

                headers = {'Content-Type': 'application/x-www-form-urlencoded',
                           'Accept': '*/*'}
                data = 'username=admin&password=password&user_token=' + \
                    csrf_token + '&Login=Login'

                request2 = HTTPRequest(url, headers=headers,
                                       cookies=cookie, data=data)
                response = request2.do_request()

                url = 'http://' + host + '/dvwa/vulnerabilities/sqli/'
                params = {'id': 'a\'', 'Submit': 'Submit'}
                expected_regex = kargs['expected_regex']
                failure_regex = kargs['failure_regex']

                kwargs = {'url': url, 'params': params,
                          'expected_regex': expected_regex,
                          'failure_regex': failure_regex,
                          'headers': headers,
                          'cookies': cookie}
                func(**kwargs)
            return do_dvwa
    return my_decorator
