# -*- coding: utf-8 -*-

"""HTTP helper."""

# standard imports
import re

# 3rd party imports
try:
    from urlparse import parse_qsl as parse_qsl
    from urlparse import urlparse
    from urllib import quote as quote
except ImportError:
    from urllib.parse import parse_qsl as parse_qsl
    from urllib.parse import quote as quote
    from urllib.parse import urlparse

from bs4 import BeautifulSoup
from requests_oauthlib import OAuth1
from requests_ntlm import HttpNtlmAuth
import requests
# pylint: disable=import-error
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts import LOGGER
from fluidasserts.helper import banner_helper

# pylint: disable=W0212
# pylint: disable=R0902
# pylint: disable=R0913

# pylint: disable=no-member
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
    'x-xss-protection': '^1(\\s*;\\s*mode=block)?$',
    'www-authenticate': '^((?!Basic).)*$',
    'x-powered-by': '^ASP.NET'
}


class ConnError(Exception):
    """requests.ConnectionError wrapper exception."""
    pass


class HTTPSession(object):
    """Class of HTTP request objects."""

    def __init__(self, url, params=None, headers=None, method=None,
                 cookies=None, data='', files=None, auth=None, stream=False):
        """Construct method."""
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

    def do_request(self):  # noqa
        """Do HTTP request."""
        if self.method in ['PUT', 'DELETE']:
            try:
                if self.method == 'PUT':
                    ret = requests.put(self.url, verify=False,
                                       auth=self.auth,
                                       params=self.params,
                                       cookies=self.cookies,
                                       data=self.data,
                                       headers=self.headers,
                                       timeout=10)
                if self.method == 'DELETE':
                    ret = requests.delete(self.url, verify=False,
                                          auth=self.auth,
                                          params=self.params,
                                          cookies=self.cookies,
                                          data=self.data,
                                          headers=self.headers,
                                          timeout=10)
                self.response = ret
            except (requests.ConnectionError,
                    requests.exceptions.TooManyRedirects):
                raise ConnError
        else:
            try:
                if self.data == '':
                    ret = requests.get(self.url, verify=False,
                                       auth=self.auth,
                                       params=self.params,
                                       cookies=self.cookies,
                                       headers=self.headers,
                                       stream=self.stream,
                                       timeout=10)
                else:
                    ret = requests.post(self.url, verify=False,
                                        data=self.data,
                                        auth=self.auth,
                                        params=self.params,
                                        cookies=self.cookies,
                                        headers=self.headers,
                                        files=self.files,
                                        stream=self.stream,
                                        timeout=10)
                self.response = ret
                if self.response.url != self.url:
                    self.url = self.response.url

                if ret.cookies == {}:
                    if (ret.request._cookies != {} and
                            self.cookies != ret.request._cookies):
                        self.cookies = ret.request._cookies
                else:
                    self.cookies = ret.cookies
            except (requests.ConnectionError,
                    requests.exceptions.TooManyRedirects):
                raise ConnError
        return ret

    def formauth_by_statuscode(self, code):
        """Authenticate using status code as verification."""
        self.headers['Content-Type'] = \
            'application/x-www-form-urlencoded'
        self.headers['Accept'] = '*/*'

        http_req = self.do_request()

        if http_req.status_code == code:
            self.is_auth = True
            LOGGER.info('POST Authentication %s, Details=%s',
                        self.url, 'Success with ' + str(self.data))
        else:
            self.is_auth = False
            LOGGER.info('POST Authentication %s, Details=%s',
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
        """Authenticate using regex as verification."""
        self.headers['Content-Type'] = \
            'application/x-www-form-urlencoded'

        http_req = self.do_request()
        if http_req is None:
            return None
        if http_req.text.find(text) >= 0:
            self.is_auth = True
            LOGGER.debug('POST Authentication %s, Details=%s',
                         self.url, 'Success with ' + str(self.data))
        else:
            self.is_auth = False
            LOGGER.debug(
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
        """Authenticate using BASIC."""
        self.__do_auth('BASIC', user, passw)

    def ntlm_auth(self, user, passw):
        """Authenticate using NTLM."""
        self.__do_auth('NTLM', user, passw)

    def oauth_auth(self, user, passw):
        """Authenticate using OAUTH."""
        self.__do_auth('OAUTH', user, passw)

    def __do_auth(self, method, user, passw):
        """Authenticate using HTTP."""
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
                LOGGER.info('%s Auth: %s, Details=%s', method, self.url,
                            'Success with [ ' + user + ' : ' + passw + ' ]')
            else:
                self.is_auth = False
                LOGGER.info('%s Auth: %s, Details=%s', method, self.url,
                            'Fail with [ ' + user + ' : ' + passw + ' ]')
        else:
            self.is_auth = False
            LOGGER.info('%s Auth: %s, Details=%s', method, self.url,
                        'Not present')

    def get_html_value(self, field_type, field_name, field='value', enc=False):
        """Get a value from a HTML field."""
        soup = BeautifulSoup(self.response.text, 'html.parser')
        text_to_get = soup.find(field_type,
                                {'name': field_name})[field]
        if enc:
            return quote(text_to_get)
        return text_to_get

    def get_fingerprint(self):
        """Get HTTP fingerprint."""
        parsed = urlparse(self.url)
        host = parsed.netloc.split(':')[0]
        if parsed.scheme == 'http':
            if parsed.port:
                service = banner_helper.HTTPService(parsed.port)
            else:
                service = banner_helper.HTTPService()
        else:
            if parsed.port:
                service = banner_helper.HTTPSService(parsed.port)
            else:
                service = banner_helper.HTTPSService()
        return service.get_fingerprint(host)


def create_dataset(field, value_list, query_string):
    """Create dataset from values on list."""
    dataset = []
    if isinstance(query_string, str):
        data_dict = dict(parse_qsl(query_string))
    else:
        data_dict = query_string.copy()
    for value in value_list:
        data_dict[field] = value
        dataset.append(data_dict.copy())
    return dataset


def request_dataset(url, dataset_list, *args, **kwargs):
    """Request datasets and gives the results in a list."""
    kw_new = kwargs.copy()
    resp = list()
    for dataset in dataset_list:
        if 'data' in kw_new:
            kw_new['data'] = dataset
        elif 'params' in kw_new:
            kw_new['params'] = dataset
        sess = HTTPSession(url, *args, **kw_new)
        resp.append((len(sess.response.text), sess.response.status_code))
    return resp


def options_request(url, *args, **kwargs):
    """HTTP OPTIONS request."""
    try:
        return requests.options(url, verify=False, *args, **kwargs)
    except requests.ConnectionError:
        LOGGER.error('Sin acceso a %s , %s', url, 'ERROR')


def has_method(url, method, *args, **kwargs):
    """Check specific HTTP method."""
    is_method_present = options_request(url, *args, **kwargs).headers
    result = True
    if 'allow' in is_method_present:
        if method in is_method_present['allow']:
            show_open('HTTP Method {} enabled'.format(method),
                      details=dict(url=url),
                      refs='apache/restringir-metodo-http')
        else:
            show_close('HTTP Method {} disabled'.format(method),
                       details=dict(url=url),
                       refs='apache/restringir-metodo-http')
            result = False
    else:
        show_close('HTTP Method {} disabled'.format(method),
                   details=dict(url=url),
                   refs='apache/restringir-metodo-http')
        result = False
    return result


# pylint: disable=too-many-branches
def has_insecure_header(url, header, *args, **kwargs):  # noqa
    """Check if header is present."""
    try:
        http_session = HTTPSession(url, *args, **kwargs)
        headers_info = http_session.response.headers
    except ConnError:
        show_unknown('HTTP error checking {}'.format(header),
                     details=dict(url=url))
        return True

    if header == 'Access-Control-Allow-Origin':
        if 'headers' in kwargs:
            kwargs['headers'].update({'Origin':
                                      'https://www.malicious.com'})
        else:
            kwargs = {'headers': {'Origin': 'https://www.malicious.com'}}

        if header in headers_info:
            value = headers_info[header]
            if not re.match(HDR_RGX[header.lower()], value, re.IGNORECASE):
                show_open('{} HTTP header is insecure'.
                          format(header),
                          details=dict(url=url, header=header, value=value),
                          refs='apache/habilitar-headers-seguridad')
                return True
            show_close('HTTP header {} value is secure'.
                       format(header),
                       details=dict(url=url, header=header, value=value),
                       refs='apache/habilitar-headers-seguridad')
            return False
        show_close('HTTP header {} not present which is secure \
by default'.format(header),
                   details=dict(url=url, header=header),
                   refs='apache/habilitar-headers-seguridad')
        return False

    result = True

    if header == 'X-AspNet-Version' or header == 'Server':
        if header in headers_info:
            value = headers_info[header]
            show_open('{} HTTP insecure header present'.
                      format(header),
                      details=dict(url=url, header=header, value=value),
                      refs='apache/habilitar-headers-seguridad')
            result = True
        else:
            show_close('{} HTTP insecure header not present'.
                       format(header),
                       details=dict(url=url, header=header),
                       refs='apache/habilitar-headers-seguridad')
            result = False
        return result
    if header in headers_info:
        value = headers_info[header]
        if re.match(HDR_RGX[header.lower()], value, re.IGNORECASE):
            show_close('HTTP header {} is secure'.format(header),
                       details=dict(url=url, header=header, value=value),
                       refs='apache/habilitar-headers-seguridad')
            result = False
        else:
            show_open('{} HTTP header is insecure'.
                      format(header),
                      details=dict(url=url, header=header, value=value),
                      refs='apache/habilitar-headers-seguridad')
            result = True
    else:
        show_open('{} HTTP header not present'.
                  format(header),
                  details=dict(url=url, header=header),
                  refs='apache/habilitar-headers-seguridad')
        result = True

    return result
