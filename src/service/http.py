# -*- coding: utf-8 -*-

"""Modulo para verificación del protocolo HTTP.

Este modulo permite verificar vulnerabilidades propias de HTTP como:

    * Transporte plano de información,
    * Headers de seguridad no establecidos,
    * Cookies no generadas de forma segura,
"""

# standard imports
import logging
import re
import urllib
import requests

# 3rd party imports
from requests_oauthlib import OAuth1

# local imports


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
    'server': '^.*[0-9]+\\.[0-9]+.*$',
    'x-permitted-cross-domain-policies': '^\\s*master\\-only\\s*$',
    'x-xss-protection': '^1(; mode=block)?$',
    'www-authenticate': '^((?!Basic).)*$'
}


def __get_request(url, auth=None):
    """Realiza una petición GET HTTP."""
    try:
        headers = {
            'user-agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0)'}
        return requests.get(url, verify=False, auth=auth, headers=headers)
    except requests.ConnectionError:
        logging.error('Sin acceso a %s , %s', url, 'ERROR')


def __post_request(url, data=''):
    """Realiza una petición POST HTTP."""
    try:
        headers = {
            'user-agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0)'}
        # TODO(glopez): El user agent debe ser de FLUIDAsserts y parametrizable
        return requests.post(url, verify=False, data=data,
                             headers=headers, allow_redirects=False)
    except requests.ConnectionError:
        logging.error('Sin acceso a %s , %s', url, 'ERROR')


def formauth_by_statuscode(url, code, **formargs):
    """XXXXXXXXXXXXXX."""
    http_req = __post_request(url, formargs)
    if http_req.status_code == code:
        logging.info('POST Authentication %s, Details=%s, %s',
                     url, 'Success with ' + str(formargs), 'OPEN')
    else:
        logging.info('POST Authentication %s, Details=%s, %s',
                     url,
                     'Error code (' + str(http_req.status_code) +
                     ') ' + str(formargs),
                     'CLOSE')


def formauth_by_response(url, text, **formargs):
    """XXXXXXXXXXXXXX."""
    http_req = __post_request(url, formargs)
    if http_req.text.find(text) >= 0:
        logging.info('POST Authentication %s, Details=%s, %s',
                     url, 'Success with ' + str(formargs), 'OPEN')
    else:
        logging.info(
            'POST Authentication %s, Details=%s, %s',
            url,
            'Error text (' + http_req.text + ') ' + str(formargs),
            'CLOSE')


def basic_auth(url, user, passw):
    """XXXXXXXXXXXXXX."""
    resp = __get_request(url, (user, passw))
    if __get_request(url).status_code == 401:
        if resp.status_code == 200:
            logging.info(
                'HTTPBasicAuth %s, Details=%s, %s',
                url,
                'Success with [ ' + user + ' : ' + passw + ' ]',
                'OPEN')
        else:
            logging.info('HTTPBasicAuth %s, Details=%s, %s', url,
                         'Fail with [ ' + user + ' : ' + passw + ' ]', 'CLOSE')
    else:
        logging.info('HTTPBasicAuth %s, Details=%s, %s', url,
                     'HTTPBasicAuth Not present', 'CLOSE')


def oauth_auth(url, user, passw):
    """XXXXXXXXXXXXXX."""
    resp = __get_request(url, OAuth1(user, passw))
    if __get_request(url).status_code == 401:
        if resp.status_code == 200:
            logging.info(
                'HTTPOAuth %s, Details=%s, %s',
                url,
                'Success with [ ' + user + ' : ' + passw + ' ]',
                'OPEN')
        else:
            logging.info('HTTPOAuth %s, Details=%s, %s', url,
                         'Fail with [ ' + user + ' : ' + passw + ' ]', 'CLOSE')
    else:
        logging.info('HTTPOAuth %s, Details=%s, %s', url,
                     'HTTPOAuth Not present', 'CLOSE')


def __has_secure_header(url, header):
    """Check if header is present."""
    headers_info = __get_request(url).headers
    result = False
    if header in headers_info:
        value = headers_info[header]
        state = (lambda val: 'CLOSE' if re.match(
            HDR_RGX[header],
            value) is not None else 'OPEN')(value)
        logging.info('%s HTTP header %s, Details=%s, %s',
                     header, url, value, state)
        result = state == 'CLOSE'
    else:
        logging.info('%s HTTP header %s, Details=%s, %s',
                     header, url, 'Not Present', 'OPEN')
        result = False

    return result


def __check_result(url, header):
    """Returns result according to the assert."""
    result = True
    if __has_secure_header(url, header) is True:
        result = False
    else:
        result = True

    return result


def __options_request(url):
    """HTTP OPTIONS request."""
    try:
        return requests.options(url, verify=False)
    except requests.ConnectionError:
        logging.error('Sin acceso a %s , %s', url, 'ERROR')


def __has_method(url, method):
    """Check specific HTTP method."""
    is_method_present = __options_request(url).headers
    result = True
    if 'allow' in is_method_present:
        if method in is_method_present['allow']:
            logging.info('%s HTTP Method %s, Details=%s, %s',
                         url, method, 'Is Present', 'OPEN')
        else:
            logging.info('%s HTTP Method %s, Details=%s, %s',
                         url, method, 'Not Present', 'CLOSE')
            result = False
    else:
        logging.info('Method %s not allowed in %s', method, url)
        result = False
    return result


def is_header_x_asp_net_version_missing(url):
    """Check if x-aspnet-version header is missing."""
    return __check_result(url, 'x-aspnet-version')


def is_header_access_control_allow_origin_missing(url):
    """Check if access-control-allow-origin header is missing."""
    return __check_result(url, 'access-control-allow-origin')


def is_header_cache_control_missing(url):
    """Check if cache-control header is missing."""
    return __check_result(url, 'cache-control')


def is_header_content_security_policy_missing(url):
    """Check if content-security-policy header is missing."""
    return __check_result(url, 'content-security-policy')


def is_header_content_type_missing(url):
    """Check if content-security-policy header is missing."""
    return __check_result(url, 'content-type')


def is_header_expires_missing(url):
    """Check if content-security-policy header is missing."""
    return __check_result(url, 'expires')


def is_header_pragma_missing(url):
    """Check if pragma header is missing."""
    return __check_result(url, 'pragma')


def is_header_server_missing(url):
    """Check if server header is missing."""
    return __check_result(url, 'server')


def is_header_x_powered_by_missing(url):
    """Check if x-powered-by header is missing."""
    return __check_result(url, 'x-powered-by')


def is_header_x_content_type_options_missing(url):
    """Check if x-content-type-options header is missing."""
    return __check_result(url, 'x-content-type-options')


def is_header_x_frame_options_missing(url):
    """Check if x-frame-options header is missing."""
    return __check_result(url, 'x-frame-options')


def is_header_x_permitted_cross_domain_policies_missing(url):
    """Check if x-permitted-cross-domain-policies header is missing."""
    return __check_result(url, 'x-permitted-cross-domain-policies')


def is_header_x_xxs_protection_missing(url):
    """Check if x-xss-protection header is missing."""
    return __check_result(url, 'x-xss-protection')


def is_header_hsts_missing(url):
    """Check if strict-transport-security header is missing."""
    return __check_result(url, 'strict-transport-security')


def is_basic_auth_enabled(url):
    """Check if BASIC authentication is enabled."""
    return __check_result(url, 'www-authenticate')


def has_trace_method(url):
    """Check HTTP TRACE."""
    return __has_method(url, 'TRACE')


def has_delete_method(url):
    """Check HTTP DELETE."""
    return __has_method(url, 'DELETE')


def has_put_method(url):
    """Check HTTP PUT."""
    return __has_method(url, 'PUT')


def generic_http_assert(url, method, expected_regex,
                        failure_regex, headers=None, data=None):
    """Generic HTTP assert method."""

    opener = urllib.request.build_opener(urllib.request.HTTPHandler)

    if data is not None:
        post_data = urllib.parse.urlencode(data)
    if data is not None and headers is not None:
        response = opener.open(url, data, headers)
    else:
        response = opener.open(url)
    the_page = response.read().decode('utf-8')

    if re.search(str(failure_regex), the_page):
        logging.info('%s HTTP assertion failed, Details=%s, %s, %s',
                     url, method, failure_regex, 'OPEN')
        return True
    elif re.search(str(expected_regex), the_page) is None:
        logging.info('%s HTTP assertion not found, Details=%s, %s, %s',
                     url, method, expected_regex, 'OPEN')
        return True
    elif re.search(str(expected_regex), the_page):
        logging.info('%s HTTP assertion succeed, Details=%s, %s, %s',
                     url, method, expected_regex, 'CLOSE')
        return False
