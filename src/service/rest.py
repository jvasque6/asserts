# -*- coding: utf-8 -*-

"""Modulo para verificacion del webservices expuestos o vulnerables.

Este modulo permite verificar vulnerabilidades sobre webservices:

    * Uso de REST API sin credenciales o token
"""
# standard imports
import logging

# third party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track
from fluidasserts.helper import http_helper

logger = logging.getLogger('FLUIDAsserts')


@track
def has_access(url, *args, **kwargs):
    """Check if a bad text is present."""
    http_session = http_helper.HTTPSession(url, *args, **kwargs)
    ok_access_list = [200]
    if http_session.response.status_code in ok_access_list:
        logger.info('%s: Access available to %s', show_open(), url)
        return True
    logger.info('%s: Access not available to %s', show_close(), url)
    return False


@track
def has_trace_method(url):
    """Check HTTP TRACE."""
    return http_helper.has_method(url, 'TRACE')


@track
def has_delete_method(url):
    """Check HTTP DELETE."""
    return http_helper.has_method(url, 'DELETE')


@track
def has_put_method(url):
    """Check HTTP PUT."""
    return http_helper.has_method(url, 'PUT')


@track
def accepts_empty_content_type(url, *args, **kwargs):
    """Check if given URL accepts empty Content-Type requests."""
    expected_codes = [406, 415]
    error_codes = [400, 401, 403, 404, 500]
    session = http_helper.HTTPSession(url, *args, **kwargs)

    if session.response.status_code in error_codes:
        logger.info('%s: URL %s returned error',
                    show_unknown(), url)
        return True
    if session.response.status_code not in expected_codes:
        logger.info('%s: URL %s accepts empty Content-Type requests',
                    show_open(), url)
        return True
    logger.info('%s: URL %s rejects empty Content-Type requests',
                show_close(), url)
    return False


@track
def accepts_insecure_accept_header(url, *args, **kwargs):
    """Check if given URL accepts insecure Accept request header value."""
    expected_codes = [406, 415]
    error_codes = [400, 401, 403, 404, 500]
    if 'headers' in kwargs:
        kwargs['headers'].update({'Accept': '*/*'})
    else:
        kwargs = {'headers': {'Accept': '*/*'}}
    session = http_helper.HTTPSession(url, *args, **kwargs)

    if session.response.status_code in error_codes:
        logger.info('%s: URL %s returned error',
                    show_unknown(), url)
        return True
    if session.response.status_code not in expected_codes:
        logger.info('%s: URL %s accepts insecure Accept request header value',
                    show_open(), url)
        return True
    logger.info('%s: URL %s rejects insecure Accept request header value',
                show_close(), url)
    return False


@track
def is_header_x_content_type_options_missing(url, *args, **kwargs):
    """Check if x-content-type-options header is missing."""
    return http_helper.has_insecure_header(url,
                                           'X-Content-Type-Options',
                                           *args, **kwargs)


@track
def is_header_x_frame_options_missing(url, *args, **kwargs):
    """Check if x-frame-options header is missing."""
    return http_helper.has_insecure_header(url, 'X-Frame-Options',
                                           *args, **kwargs)


@track
def is_header_access_control_allow_origin_missing(url, *args, **kwargs):
    """Check if access-control-allow-origin header is missing."""
    return http_helper.has_insecure_header(url,
                                           'Access-Control-Allow-Origin',
                                           *args, **kwargs)


@track
def is_not_https_required(url):
    """Check if HTTPS is always forced on a given url."""
    assert url.startswith('http://')
    http_session = http_helper.HTTPSession(url)
    if http_session.url.startswith('https'):
        logger.info('%s: HTTPS is forced on URL, Details=%s',
                    show_close(), http_session.url)
        return False
    else:
        logger.info('%s: HTTPS is not forced on URL, Details=%s',
                    show_open(), http_session.url)
        return True
