# -*- coding: utf-8 -*-

"""Modulo de ayuda HTTP
"""

# standard imports
import logging
import urllib
import re
import requests

# 3rd party imports
from bs4 import BeautifulSoup

# local imports
# none


def get_request(url, headers={}, cookies=None, params=None, auth=None):
    """Realiza una petición GET HTTP."""
    try:
        headers['user-agent'] = \
                'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0)'
        return requests.get(url, verify=False,
                            auth=auth, params=params,
                            cookies=cookies, headers=headers)
    except requests.ConnectionError:
        logging.error('Sin acceso a %s , %s', url, 'ERROR')


def post_request(url, headers={}, cookies=None, params=None, data=''):
    """Realiza una petición POST HTTP."""
    try:
        headers['user-agent'] = \
                'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0)'
        return requests.post(url, verify=False, data=data,
                             cookies=cookies, params=params,
                             headers=headers, allow_redirects=True)
    except requests.ConnectionError:
        logging.error('Sin acceso a %s , %s', url, 'ERROR')


def generic_http_assert(url, expected_regex, failure_regex,
                        headers={}, cookies=None, params=None, data=None):
    """Generic HTTP assert method."""

    if data is None:
        response = get_request(url, headers=headers, cookies=cookies,
                               params=params)
    else:
        response = post_request(url, headers=headers, cookies=cookies,
                                params=params, data=data)

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
