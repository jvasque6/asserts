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

# 3rd party imports
# None

# local imports
from fluidasserts.helper import http_helper


def generic_http_assert(url, expected_regex, params=None,
                        data='', cookies={}):
    """Generic HTTP assert method."""
    http_session = http_helper.HTTPSession(url, params=params,
                                           data=data, cookies=cookies)
    response = http_session.response
    the_page = response.text

    if re.search(str(expected_regex), the_page) is None:
        logging.info('%s HTTP assertion not found, Details=%s, %s',
                     http_session.url, expected_regex, 'OPEN')
        logging.info(the_page)
        return True
    else:
        logging.info('%s HTTP assertion succeed, Details=%s, %s',
                     http_session.url, expected_regex, 'CLOSE')
        logging.info(the_page)
        return False


def is_header_x_asp_net_version_missing(url):
    """Check if x-aspnet-version header is missing."""
    return http_helper.has_insecure_header(url, 'x-aspnet-version')


def is_header_access_control_allow_origin_missing(url):
    """Check if access-control-allow-origin header is missing."""
    return http_helper.has_insecure_header(url,
                                           'access-control-allow-origin')


def is_header_cache_control_missing(url):
    """Check if cache-control header is missing."""
    return http_helper.has_insecure_header(url, 'cache-control')


def is_header_content_security_policy_missing(url):
    """Check if content-security-policy header is missing."""
    return http_helper.has_insecure_header(url,
                                           'content-security-policy')


def is_header_content_type_missing(url):
    """Check if content-security-policy header is missing."""
    return http_helper.has_insecure_header(url, 'content-type')


def is_header_expires_missing(url):
    """Check if content-security-policy header is missing."""
    return http_helper.has_insecure_header(url, 'expires')


def is_header_pragma_missing(url):
    """Check if pragma header is missing."""
    return http_helper.has_insecure_header(url, 'pragma')


def is_header_server_insecure(url):
    """Check if server header is insecure."""
    return http_helper.has_insecure_header(url, 'server')


def is_header_x_powered_by_missing(url):
    """Check if x-powered-by header is missing."""
    return http_helper.has_insecure_header(url, 'x-powered-by')


def is_header_x_content_type_options_missing(url):
    """Check if x-content-type-options header is missing."""
    return http_helper.has_insecure_header(url,
                                           'x-content-type-options')


def is_header_x_frame_options_missing(url):
    """Check if x-frame-options header is missing."""
    return http_helper.has_insecure_header(url, 'x-frame-options')


def is_header_x_permitted_cross_domain_policies_missing(url):
    """Check if x-permitted-cross-domain-policies header is missing."""
    return http_helper.has_insecure_header(url,
                                           'x-permitted-cross-domain-policies')


def is_header_x_xxs_protection_missing(url):
    """Check if x-xss-protection header is missing."""
    return http_helper.has_insecure_header(url, 'x-xss-protection')


def is_header_hsts_missing(url):
    """Check if strict-transport-security header is missing."""
    return http_helper.has_insecure_header(url,
                                           'strict-transport-security')


def is_basic_auth_enabled(url):
    """Check if BASIC authentication is enabled."""
    return http_helper.has_insecure_header(url,
                                           'www-authenticate')


def has_trace_method(url):
    """Check HTTP TRACE."""
    return http_helper.has_method(url, 'TRACE')


def has_delete_method(url):
    """Check HTTP DELETE."""
    return http_helper.has_method(url, 'DELETE')


def has_put_method(url):
    """Check HTTP PUT."""
    return http_helper.has_method(url, 'PUT')


def has_sqli(url, expect, params=None, data='', cookies={}):
    """Check SQLi vuln by checking expected string."""
    return generic_http_assert(url, expect, params=params,
                               data=data, cookies=cookies)


def has_xss(url, expect, params=None, data='', cookies={}):
    """Check XSS vuln by checking expected string."""
    return generic_http_assert(url, expect, params=params,
                               data=data, cookies=cookies)


def has_command_injection(url, expect, params=None, data='', cookies={}):
    """Check command injection vuln by checking expected string."""
    return generic_http_assert(url, expect, params=params,
                               data=data, cookies=cookies)


def has_php_command_injection(url, expect, params=None, data='', cookies={}):
    """Check PHP command injection by checking expected string."""
    return generic_http_assert(url, expect, params=params,
                               data=data, cookies=cookies)


def has_session_fixation(url, expect, params=None, data=''):
    """Check session fixation by no passing cookies and authenticating."""
    return generic_http_assert(url, expect, params=params,
                               data=data, cookies=None)


def has_insecure_dor(url, expect, params=None, data='', cookies={}):
    """Check insecure direct object reference vuln."""
    return generic_http_assert(url, expect, params=params,
                               data=data, cookies=cookies)


def has_dirtraversal(url, expect, params=None, data='', cookies={}):
    """Check directory traversal vuln by checking expected string."""
    return generic_http_assert(url, expect, params=params,
                               data=data, cookies=cookies)


def is_sessionid_exposed(url, argument='sessionid', params=None,
                         data='', cookies={}):
    """Checks if resulting URL has a session ID exposed."""
    http_session = http_helper.HTTPSession(url, params=params,
                                           data=data, cookies=cookies)
    response_url = http_session.response.url

    regex = r'\b' + argument + r'\b'

    result = True
    if re.search(regex, response_url):
        result = True
        logging.info('Session ID is exposed in %s, Details=%s, %s',
                     response_url, argument, 'OPEN')
    else:
        result = False
        logging.info('Session ID is hidden in %s, Details=%s, %s',
                     response_url, argument, 'CLOSE')
    return result
