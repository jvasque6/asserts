# -*- coding: utf-8 -*-

"""Modulo de ayuda HTTP."""

# standard imports
import logging
import re
import requests

# 3rd party imports
from requests_oauthlib import OAuth1

# local imports
# none

# pylint: disable=W0212
# pylint: disable=R0902
# pylint: disable=R0913

HDR_RGX = {
    'access-control-allow-origin': '^https?:\\/\\/.*$',
    'cache-control': 'private, no-cache, no-store, max-age=0, no-transform',
    'content-security-policy': '^([a-zA-Z]+\\-[a-zA-Z]+|sandbox).*$',
    'content-type': '^(\\s)*.+(\\/|-).+(\\s)*;(\\s)*charset.*$',
    'expires': '^\\s*0\\s*$',
    'pragma': '^\\s*no-cache\\s*$',
    'strict-transport-security': '^\\s*max-age=\\s*\\d+',
    'x-content-type-options': '^\\s*nosniff\\s*$',
    'x-frame-options': '^\\s*(deny|allow-from|sameorigin).*$',
    'server': '^[^0-9]*$',
    'permitted-cross-domain-policies': '^\\s*master\\-only\\s*$',
    'x-xss-protection': '^1(; mode=block)?$',
    'www-authenticate': '^((?!Basic).)*$'
}

logger = logging.getLogger('FLUIDAsserts')


class HTTPSession(object):
    """Class of HTTP request objects."""

    def __init__(self, url, params=None, headers=None,
                 cookies=None, data='', files=None, auth=None):
        """Metodo constructur de la clase."""
        self.url = url
        self.params = params
        self.headers = headers
        self.cookies = cookies
        self.data = data
        self.auth = auth
        self.files = files
        self.response = None
        self.is_auth = False
        if self.headers is None:
            self.headers = dict()
        self.headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) \
            AppleWebKit/537.36 (KHTML, like Gecko) FLUIDAsserts/1.0'
        self.headers['Accept'] = '*/*'

        self.do_request()

    def do_request(self):
        """Realiza una peticion HTTP."""
        try:
            if self.data == '':
                ret = requests.get(self.url, verify=False,
                                   auth=self.auth,
                                   params=self.params,
                                   cookies=self.cookies,
                                   headers=self.headers)
            else:
                ret = requests.post(self.url, verify=False,
                                    data=self.data,
                                    auth=self.auth,
                                    params=self.params,
                                    cookies=self.cookies,
                                    headers=self.headers,
                                    files=self.files)
            self.response = ret
            if ret.cookies == {}:
                if ret.request._cookies != {} and \
                   self.cookies != ret.request._cookies:
                    self.cookies = ret.request._cookies
            else:
                self.cookies = ret.cookies
            return ret
        except requests.ConnectionError:
            logging.error('Sin acceso a %s , %s', self.url, 'ERROR')

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
        if http_req.text.find(text) >= 0:
            self.is_auth = True
            logger.info('POST Authentication %s, Details=%s',
                        self.url, 'Success with ' + str(self.data))
        else:
            self.is_auth = False
            logger.info(
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
        """Autentica usando BASIC HTTP."""
        self.auth = (user, passw)
        resp = self.do_request()

        self.auth = None
        request_no_auth = self.do_request()
        if request_no_auth.status_code == 401:
            if resp.status_code == 200:
                self.cookies = resp.cookies.get_dict()
                self.response = resp
                self.is_auth = True
                logger.info(
                    'HTTPBasicAuth %s, Details=%s',
                    self.url,
                    'Success with [ ' + user + ' : ' + passw + ' ]')
            else:
                self.is_auth = False
                logger.info('HTTPBasicAuth %s, Details=%s',
                            self.url,
                            'Fail with [ ' + user + ' : ' + passw + ' ]')
        else:
            self.is_auth = False
            logger.info('HTTPBasicAuth %s, Details=%s', self.url,
                        'HTTPBasicAuth Not present')

    def oauth_auth(self, user, passw):
        """XXXXXXXXXXXXXX."""
        self.auth = OAuth1(user, passw)
        resp = self.do_request()

        self.auth = None
        request_no_auth = self.do_request()
        if request_no_auth.status_code == 401:
            if resp.status_code == 200:
                self.cookies = resp.cookies.get_dict()
                self.response = resp
                self.is_auth = True
                logger.info(
                    'HTTPOAuth %s, Details=%s',
                    self.url,
                    'Success with [ ' + user + ' : ' + passw + ' ]')
            else:
                self.is_auth = False
                logger.info('HTTPOAuth %s, Details=%s', self.url,
                            'Fail with [ ' + user + ' : ' + passw + ' ]')
        else:
            self.is_auth = False
            logger.info('HTTPOAuth %s, Details=%s', self.url,
                        'HTTPOAuth Not present')


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
            logger.info('%s HTTP Method %s, Details=%s, %s',
                        url, method, 'Is Present', 'OPEN')
        else:
            logger.info('%s HTTP Method %s, Details=%s, %s',
                        url, method, 'Not Present', 'CLOSE')
            result = False
    else:
        logger.info('Method %s not allowed in %s', method, url)
        result = False
    return result


def has_insecure_header(url, header):
    """Check if header is present."""
    http_session = HTTPSession(url)
    headers_info = http_session.response.headers

    result = True
    if header in headers_info:
        value = headers_info[header]
        state = (lambda val: 'CLOSE' if re.match(
            HDR_RGX[header],
            value) is not None else 'OPEN')(value)
        logger.info('%s HTTP header %s, Details=%s, %s',
                    header, url, value, state)
        result = state != 'CLOSE'
    else:
        logger.info('%s HTTP header %s, Details=%s, %s',
                    header, url, 'Not Present', 'OPEN')
        result = True

    return result
