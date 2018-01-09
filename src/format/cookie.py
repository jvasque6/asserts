# -*- coding: utf-8 -*-

"""Modulo para verificaciones de Cookies HTTP.

Este modulo deberia considerarse su anexion al verificador de http.py pues como
tal las cookies son parte de dicho protocolo.
"""


# standard imports
# None

# 3rd party imports
import logging

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.helper import http_helper
from fluidasserts.utils.decorators import track

LOGGER = logging.getLogger('FLUIDAsserts')


def __has_not_http_only(cookie_name, url=None, cookie_jar=None):
    """Verifica si la cookie tiene el atributo httponly."""
    result = show_unknown()
    if url is None and cookie_jar is None:
        LOGGER.info('%s: Cookie check for "%s", Details=%s', result,
                    cookie_name, 'HttpOnly')
        return result != show_close()
    if url is not None:
        sess = http_helper.HTTPSession(url)
        cookielist = sess.cookies
    else:
        cookielist = cookie_jar
    if cookielist is None:
        LOGGER.info('%s: %s Cookie not present', result, cookie_name)
        return result != show_close()
    for cookie in cookielist:
        if cookie.name == cookie_name:
            if cookie.has_nonstandard_attr('HttpOnly') or \
               cookie.has_nonstandard_attr('httponly'):
                result = show_close()
            else:
                result = show_open()
    LOGGER.info('%s: Cookie check for "%s", Details=%s', result,
                cookie_name, 'HttpOnly')
    return result != show_close()


def __has_not_secure(cookie_name, url=None, cookie_jar=None):
    """Verifica si la cookie tiene el atributo secure."""
    result = show_unknown()
    if url is None and cookie_jar is None:
        LOGGER.info('%s: Cookie check for "%s", Details=%s', result,
                    cookie_name, 'Secure')
        return result != show_close()
    if url is not None:
        sess = http_helper.HTTPSession(url)
        cookielist = sess.cookies
    else:
        cookielist = cookie_jar
    if cookielist is None:
        LOGGER.info('%s: %s Cookie not present', result, cookie_name)
        return result != show_close()
    for cookie in cookielist:
        if cookie.name == cookie_name:
            if cookie.secure:
                result = show_close()
            else:
                result = show_open()
    LOGGER.info('%s: Cookie check for "%s", Details=%s', result,
                cookie_name, 'Secure')
    return result != show_close()


@track
def has_not_httponly_set(cookie_name, url):
    """Verifica si la cookie tiene el atributo httponly."""
    return __has_not_http_only(cookie_name, url=url)


@track
def has_not_httponly_in_cookiejar(cookie_name, cookie_jar):
    """Verifica si la cookie tiene el atributo httponly."""
    return __has_not_http_only(cookie_name, cookie_jar=cookie_jar)


@track
def has_not_secure_set(cookie_name, url):
    """Verifica si la cookie tiene el atributo secure."""
    return __has_not_secure(cookie_name, url=url)


@track
def has_not_secure_in_cookiejar(cookie_name, cookie_jar):
    """Verifica si la cookie tiene el atributo secure."""
    return __has_not_secure(cookie_name, cookie_jar=cookie_jar)
