# -*- coding: utf-8 -*-

"""Modulo de ayuda HTTP."""

# standard imports
import logging
import re

# 3rd party imports
try:
    from urlparse import parse_qsl as parse_qsl
    from urllib import quote as quote
except ImportError:
    from urllib.parse import parse_qsl as parse_qsl
    from urllib.parse import quote as quote

from bs4 import *
from requests_oauthlib import OAuth1
import requests
from requests_ntlm import HttpNtlmAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown

# pylint: disable=W0212
# pylint: disable=R0902
# pylint: disable=R0913

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

HDR_RGX = {
    'access-control-allow-origin': '^https?:\\/\\/.*$',
    'cache-control': '(?=.*must-revalidate)(?=.*no-cache)(?=.*no-store)',
    'content-security-policy': '^([a-zA-Z]+\\-[a-zA-Z]+|sandbox).*$',
    'content-type': '^(\\s)*.+(\\/|-).+(\\s)*;(\\s)*charset.*$',
    'expires': '^\\s*0\\s*$',
    'pragma': '^\\s*no-cache\\s*$',
    'strict-transport-security': '^\\s*max-age=\\s*\\d+',
    'x-content-type-options': '^\\s*nosniff\\s*$',
    'x-frame-options': '^\\s*(deny|allow-from|sameorigin).*$',
    'server': '^[^0-9]*$',
    'x-permitted-cross-domain-policies': '^\\s*master\\-only\\s*$',
    'x-xss-protection': '^1(; mode=block)?$',
    'www-authenticate': '^((?!Basic).)*$'
}

logger = logging.getLogger('FLUIDAsserts')


class HTTPSession(object):
    """Class of HTTP request objects."""

    def __init__(self, url, params=None, headers=None, method=None,
                 cookies=None, data='', files=None, auth=None, stream=False):
        """Metodo constructor de la clase."""
        self.url = url
        self.params = params
        self.headers = headers
        self.cookies = cookies
        self.data = data
        self.auth = auth
        self.files = files
        self.method = method
        if self.method:
            assert self.method in ['PUT', 'DELETE']
        self.response = None
        self.is_auth = False
        self.stream = stream
        if self.headers is None:
            self.headers = dict()
        if 'User-Agent' not in self.headers:
            self.headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64; \
rv:45.0) Gecko/20100101 Firefox/45.0'
        if 'Accept' not in self.headers:
            self.headers['Accept'] = '*/*'
        if 'Accept-Language' not in self.headers:
            self.headers['Accept-Language'] = 'en-US,en;q=0.5'

        self.do_request()

    def do_request(self):
        """Realiza una peticion HTTP."""
        try:
            if self.method == 'PUT':
                ret = requests.put(self.url, verify=False,
                                   auth=self.auth,
                                   params=self.params,
                                   cookies=self.cookies,
                                   data=self.data,
                                   headers=self.headers)
            if self.method == 'DELETE':
                ret = requests.delete(self.url, verify=False,
                                      auth=self.auth,
                                      params=self.params,
                                      cookies=self.cookies,
                                      data=self.data,
                                      headers=self.headers)
            if self.data == '':
                ret = requests.get(self.url, verify=False,
                                   auth=self.auth,
                                   params=self.params,
                                   cookies=self.cookies,
                                   headers=self.headers,
                                   stream=self.stream)
            else:
                if not self.files:
                    if 'Content-Type' not in self.headers:
                        self.headers['Content-Type'] = \
                            'application/x-www-form-urlencoded'
                ret = requests.post(self.url, verify=False,
                                    data=self.data,
                                    auth=self.auth,
                                    params=self.params,
                                    cookies=self.cookies,
                                    headers=self.headers,
                                    files=self.files,
                                    stream=self.stream)
            self.response = ret
            if self.response.url != self.url:
                self.url = self.response.url

            if ret.cookies == {}:
                if ret.request._cookies != {} and \
                   self.cookies != ret.request._cookies:
                    self.cookies = ret.request._cookies
            else:
                self.cookies = ret.cookies
            return ret
        except requests.ConnectionError:
            logging.error('Sin acceso a %s , %s', self.url, 'ERROR')
            raise

    def formauth_by_statuscode(self, code):
        """Autentica y verifica autenticacion usando codigo HTTP."""
        self.headers['Content-Type'] = \
            'application/x-www-form-urlencoded'
        self.headers['Accept'] = '*/*'

        http_req = self.do_request()

        if http_req.status_code == code:
            self.is_auth = True
            logger.info('POST Authentication %s, Details=%s',
                        self.url, 'Success with ' + str(self.data))
        else:
            self.is_auth = False
            logger.info('POST Authentication %s, Details=%s',
                        self.url,
                        'Error code (' + str(http_req.status_code) +
                        ') ' + str(self.data))

        if http_req.cookies == {}:
            if http_req.request._cookies != {} and \
               self.cookies != http_req.request._cookies:
                self.cookies = http_req.request._cookies
        else:
            self.cookies = http_req.cookies
        self.response = http_req
        self.data = ''
        return http_req

    def formauth_by_response(self, text):
        """Autentica y verifica autenticacion usando regex."""
        self.headers['Content-Type'] = \
            'application/x-www-form-urlencoded'

        http_req = self.do_request()
        if http_req is None:
            return None
        if http_req.text.find(text) >= 0:
            self.is_auth = True
            logger.debug('POST Authentication %s, Details=%s',
                         self.url, 'Success with ' + str(self.data))
        else:
            self.is_auth = False
            logger.debug(
                'POST Authentication %s, Details=%s',
                self.url,
                'Error text (' + http_req.text + ') ' + str(self.data))

        if http_req.cookies == {}:
            if http_req.request._cookies != {} and \
               self.cookies != http_req.request._cookies:
                self.cookies = http_req.request._cookies
        else:
            self.cookies = http_req.cookies
        self.response = http_req
        self.data = ''
        del self.headers['Content-Type']
        return http_req

    def basic_auth(self, user, passw):
        self.__do_auth('BASIC', user, passw)

    def ntlm_auth(self, user, passw):
        self.__do_auth('NTLM', user, passw)

    def oauth_auth(self, user, passw):
        self.__do_auth('OAUTH', user, passw)

    def __do_auth(self, method, user, passw):
        """Autentica usando HTTP."""
        if method == 'BASIC':
            self.auth = (user, passw)
        elif method == 'NTLM':
            self.auth = HttpNtlmAuth(user, passw)
        elif method == 'OAUTH':
            self.auth = OAuth1(user, passw)
        resp = self.do_request()

        self.auth = None
        request_no_auth = self.do_request()
        if request_no_auth.status_code == 401:
            if resp.status_code == 200:
                self.cookies = resp.cookies
                self.response = resp
                self.is_auth = True
                logger.info(
                    '%s Auth: %s, Details=%s', method,  self.url,
                    'Success with [ ' + user + ' : ' + passw + ' ]')
            else:
                self.is_auth = False
                logger.info(' %s Auth: %s, Details=%s', method, self.url,
                            'Fail with [ ' + user + ' : ' + passw + ' ]')
        else:
            self.is_auth = False
            logger.info('%s Auth: %s, Details=%s', method, self.url,
                        'Not present')

    def get_html_value(self, field_type, field_name, field='value', enc=False):
        soup = BeautifulSoup(self.response.text, 'html.parser')
        text_to_get = soup.find(field_type,
                                {'name': field_name})[field]
        if enc:
            return quote(text_to_get)
        return text_to_get


def create_dataset(field, value_list, query_string):
    dataset = []
    if type(query_string) == str:
        data_dict = dict(parse_qsl(query_string))
    else:
        data_dict = query_string.copy()
    for value in value_list:
        data_dict[field] = value
        dataset.append(data_dict.copy())
    return dataset


def options_request(url):
    """HTTP OPTIONS request."""
    try:
        return requests.options(url, verify=False)
    except requests.ConnectionError:
        logging.error('Sin acceso a %s , %s', url, 'ERROR')


def has_method(url, method):
    """Check specific HTTP method."""
    is_method_present = options_request(url).headers
    result = True
    if 'allow' in is_method_present:
        if method in is_method_present['allow']:
            logger.info('%s: %s HTTP Method %s, Details=%s',
                        show_open(), url, method, 'Is Present')
        else:
            logger.info('%s: %s HTTP Method %s, Details=%s',
                        show_close(), url, method, 'Not Present')
            result = False
    else:
        logger.info('%s: Method %s not allowed in %s', show_close(),
                    method, url)
        result = False
    return result


def has_insecure_header(url, header, *args, **kwargs):
    """Check if header is present."""
    try:
        if header == 'Access-Control-Allow-Origin':
            if 'headers' in kwargs:
                kwargs['headers'].update({'Origin': 'https://www.malicious.com'})
            else:
                kwargs = {'headers': {'Origin': 'https://www.malicious.com'}}
        http_session = HTTPSession(url, *args, **kwargs)
        headers_info = http_session.response.headers
    except requests.ConnectionError:
        logger.info('%s: %s HTTP error checking %s, Details=Could not connect',
                    show_unknown(), header, url)
        return True
    result = True
    if header == 'X-AspNet-Version' or header == 'Server':
        if header in headers_info:
            logger.info('%s: %s HTTP insecure header present in %s',
                        show_open(), header, url)
            return True
        else:
            logger.info('%s: %s HTTP insecure header not present in %s',
                        show_close(), header, url)
            return False
    if header in headers_info:
        value = headers_info[header]
        state = (lambda val: show_close() if re.match(
            HDR_RGX[header.lower()],
            value, re.IGNORECASE) is not None else show_open())(value)
        logger.info('%s: %s HTTP header %s, Details=%s',
                    state, header, url, value)
        result = state != show_close()
    else:
        logger.info('%s: %s HTTP header %s, Details=%s',
                    show_open(), header, url, 'Not Present')
        result = True

    return result
