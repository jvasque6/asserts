# -*- coding: utf-8 -*-

"""Modulo para verificaciones de Cookies HTTP.

Este modulo deberia considerarse su anexion al verificador de http.py pues como
tal las cookies son parte de dicho protocolo.
"""


# standard imports
try:
    from http.cookies import BaseCookie
except ImportError:
    from Cookie import BaseCookie

# 3rd party imports
import logging

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.helper import http_helper

logger = logging.getLogger('FLUIDAsserts')


def __has_not_attribute(url, cookie_name, attribute):
    """Verifica si la cookie tiene el atributo httponly."""
    http_req = http_helper.HTTPSession(url)
    try:
        cookielist = BaseCookie(http_req.response.headers['set-cookie'])
    except KeyError:
        logger.info('%s: %s HTTP cookie %s, Details=%s',
                    show_unknown(), cookie_name, url, 'Not Present')
        return False
    result = show_open()
    if cookie_name in cookielist:
        if cookielist[cookie_name][attribute]:
            result = show_close()
        logger.info('%s: %s HTTP cookie check for "%s" in %s, Details=%s',
                    result, cookie_name, attribute, url,
                    cookielist[cookie_name])
    else:
        logger.info('%s: %s HTTP cookie %s, Details=%s',
                    show_unknown(), cookie_name, url, 'Not Present')
    return result == show_open()


def has_not_http_only(url, cookie_name):
    """Verifica si la cookie tiene el atributo httponly."""
    attribute = 'httponly'
    return __has_not_attribute(url, cookie_name, attribute)


def has_not_secure(url, cookie_name):
    """Verifica si la cookie tiene el atributo secure."""
    attribute = 'secure'
    return __has_not_attribute(url, cookie_name, attribute)
