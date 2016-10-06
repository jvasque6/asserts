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
    'strict-transport-security': '^\\s*max\\-age=\\s*\\d+\\s.*',
    'x-content-type-options': '^\\s*nosniff\\s*$',
    'x-frame-options': '^\\s*(deny|allow-from|sameorigin).*$',
    'server': '^.*[0-9]+\\.[0-9]+.*$',
    'x-permitted-cross-domain-policies': '^\\s*master\\-only\\s*$',
    'x-xss-protection': '^1(; mode=block)?$'
}


def __get_request(url, auth=None):
    """Realiza una petición GET HTTP."""
    try:
        headers = {
            'user-agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0)'}
        return requests.get(url, verify=False, auth=auth, headers=headers)
    except ConnectionError:
        logging.error('Sin acceso a %s , %s', url, 'ERROR')


def __post_request(url, data=''):
    """Realiza una petición POST HTTP."""
    try:
        headers = {
            'user-agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0)'}
        # TODO(glopez): El user agent debe ser de FLUIDAsserts y parametrizable
        return requests.post(url, verify=False, data=data,
                             headers=headers, allow_redirects=False)
    except ConnectionError:
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


def has_header_x_asp_net_version(url):
    """XXXXXXXXXXXXXX."""
    headers_info = __get_request(url).headers
    if 'x-aspnet-version' in headers_info:
        value = headers_info['x-aspnet-version']
        state = (lambda val: 'OPEN' if re.match(
            HDR_RGX['server'], value) is not None else 'CLOSE')(value)
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'x-aspnet-version', url, value, state)
    else:
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'x-aspnet-version', url, 'Not Present', 'OPEN')


def has_header_access_control_allow_origin(url):
    """XXXXXXXXXXXXXX."""
    result = True
    headers_info = __get_request(url).headers
    if 'access-control-allow-origin' in headers_info:
        value = headers_info['access-control-allow-origin']
        result = (
            lambda val: False if re.match(
                HDR_RGX['access-control-allow-origin'],
                val) is not None else True)(value)
        state = 'OPEN' if result else 'CLOSE'
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'access-control-allow-origin', url, value, state)
    else:
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'access-control-allow-origin', url, 'Not Present', 'OPEN')
    return result


def has_header_cache_control(url):
    """XXXXXXXXXXXXXX."""
    result = True
    headers_info = __get_request(url).headers
    if 'cache-control' in headers_info:
        value = headers_info['cache-control']
        result = (lambda val: False if re.match(
            HDR_RGX['cache-control'], val) is not None else True)(value)
        state = 'OPEN' if result else 'CLOSE'
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'cache-control', url, value, state)
    else:
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'cache-control', url, 'Not Present', 'OPEN')
    return result


def has_header_content_security_policy(url):
    """XXXXXXXXXXXXXX."""
    headers_info = __get_request(url).headers
    if 'content-security-policy' in headers_info:
        value = headers_info['content-security-policy']
        state = (
            lambda val: 'CLOSE' if re.match(
                HDR_RGX['content-security-policy'],
                val) is not None else 'OPEN')(value)
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'content-security-policy', url, value, state)
    else:
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'content-security-policy', url, 'Not Present', 'OPEN')


def has_header_content_type(url):
    """XXXXXXXXXXXXXX."""
    headers_info = __get_request(url).headers
    if 'content-type' in headers_info:
        value = headers_info['content-type']
        state = (lambda val: 'CLOSE' if re.match(
            HDR_RGX['content-type'], val) is not None else 'OPEN')(value)
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'content-type', url, value, state)
    else:
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'content-type', url, 'Not Present', 'OPEN')


def has_header_expires(url):
    """XXXXXXXXXXXXXX."""
    headers_info = __get_request(url).headers
    if 'expires' in headers_info:
        value = headers_info['expires']
        state = (lambda val: 'CLOSE' if re.match(
            HDR_RGX['expires'], val) is not None else 'OPEN')(value)
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'expires', url, value, state)
    else:
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'expires', url, 'Not Present', 'OPEN')


def has_header_pragma(url):
    """XXXXXXXXXXXXXX."""
    headers_info = __get_request(url).headers
    if 'pragma' in headers_info:
        value = headers_info['pragma']
        state = (lambda val: 'CLOSE' if re.match(
            HDR_RGX['pragma'], val) is not None else 'OPEN')(value)
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'pragma', url, value, state)
    else:
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'pragma', url, 'Not Present', 'OPEN')


def has_header_server(url):
    """XXXXXXXXXXXXXX."""
    headers_info = __get_request(url).headers
    if 'server' in headers_info:
        value = headers_info['server']
        state = (lambda val: 'OPEN' if re.match(
            HDR_RGX['server'], value) is not None else 'CLOSE')(value)
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'server', url, value, state)
    else:
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'server', url, 'Not Present', 'OPEN')


def has_header_x_powered_by(url):
    """XXXXXXXXXXXXXX."""
    headers_info = __get_request(url).headers
    if 'x-powered-by' in headers_info:
        value = headers_info['x-powered-by']
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'server', url, value, 'OPEN')
    else:
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'server', url, 'Not Present', 'CLOSE')


def has_header_x_content_type_options(url):
    """XXXXXXXXXXXXXX."""
    headers_info = __get_request(url).headers
    if 'x-content-type-options' in headers_info:
        value = headers_info['x-content-type-options']
        state = (
            lambda val: 'CLOSE' if re.match(
                HDR_RGX['x-content-type-options'],
                val) is not None else 'OPEN')(value)
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'x-content-type-options', url, value, state)
    else:
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'x-content-type-options', url, 'Not Present', 'OPEN')


def has_header_x_frame_options(url):
    """XXXXXXXXXXXXXX."""
    headers_info = __get_request(url).headers
    if 'x-frame-options' in headers_info:
        value = headers_info['x-frame-options']
        state = (lambda val: 'CLOSE' if re.match(
            HDR_RGX['x-frame-options'], val) is not None else 'OPEN')(value)
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'x-frame-options', url, value, state)
    else:
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'x-frame-options', url, 'Not Present', 'OPEN')


def has_header_x_permitted_cross_domain_policies(url):
    """XXXXXXXXXXXXXX."""
    headers_info = __get_request(url).headers
    if 'x-permitted-cross-domain-policies' in headers_info:
        value = headers_info['x-permitted-cross-domain-policies']
        state = (
            lambda val: 'CLOSE' if re.match(
                HDR_RGX['x-permitted-cross-domain-policies'],
                val) is not None else 'OPEN')(value)
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'x-permitted-cross-domain-policies', url, value, state)
    else:
        logging.info(
            '%s HTTP header %s, Details=%s, %s',
            'x-permitted-cross-domain-policies',
            url,
            'Not Present',
            'OPEN')


def has_header_x_xxs_protection(url):
    """XXXXXXXXXXXXXX."""
    headers_info = __get_request(url).headers
    if 'x-xss-protection' in headers_info:
        value = headers_info['x-xss-protection']
        state = (lambda val: 'CLOSE' if re.match(
            HDR_RGX['x-xss-protection'], value) is not None else 'OPEN')(value)
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'x-xss-protection', url, value, state)
    else:
        logging.info('%s HTTP header %s, Details=%s, %s',
                     'x-xss-protection', url, 'Not Present', 'OPEN')


def __options_request(url):
    """HTTP OPTIONS request."""
    try:
        return requests.options(url,verify=False)
    except ConnectionError:
        logging.error('Sin acceso a %s , %s', url, 'ERROR')


def has_trace_method(url):
    """check HTTP TRACE."""
    is_trace_present = __options_request(url).headers
    if 'allow' in is_trace_present:
        if 'TRACE' in is_trace_present['allow']:
            logging.info('%s HTTP Method %s, Details=%s, %s', url, 'TRACE', 'Is Present', 'OPEN')
        else:
            logging.info('%s HTTP Method %s, Details=%s, %s', url, 'TRACE', 'Not Present', 'CLOSE')
    else:
        logging.info('Method not allowed in %s', url)


def has_delete_method(url):
    """check HTTP DELETE."""
    is_delete_present = __options_request(url).headers
    if 'allow' in is_delete_present:
        if 'DELETE' in is_delete_present['allow']:
            logging.info('%s HTTP Method %s, Details=%s, %s', url, 'DELETE', 'Is Present', 'OPEN')
        else:
            logging.info('%s HTTP Method %s, Details=%s, %s', url, 'DELETE', 'Not Present', 'CLOSE')
    else:
        logging.info('Method not allowed in %s', url)


def has_put_method(url):
    """check HTTP PUT."""
    is_put_present = __options_request(url).headers
    if 'allow' in is_put_present:
        if 'PUT' in is_put_present['allow']:
            logging.info('%s HTTP Method %s, Details=%s, %s', url, 'PUT', 'Is Present', 'OPEN')
        else:
            logging.info('%s HTTP Method %s, Details=%s, %s', url, 'PUT', 'Not Present', 'CLOSE')
    else:
        logging.info('Method not allowed in %s', url)
