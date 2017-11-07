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
    expected_codes = [403, 406, 415]
    session = http_helper.HTTPSession(url, *args, **kwargs)

    if session.response.status_code not in expected_codes:
        logger.info('%s: URL %s accepts empty Content-Type requests',
                    show_open(), url)
        return True
    logger.info('%s: URL %s rejects empty Content-Type requests',
                show_close(), url)
    return False
