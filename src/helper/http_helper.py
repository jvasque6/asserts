# -*- coding: utf-8 -*-

"""Modulo de ayuda HTTP
"""

# standard imports
import logging
import re
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
