# -*- coding: utf-8 -*-

"""Modulo para verificaciones de Cookies HTTP.

Este modulo deberia considerarse su anexion al verificador de http.py pues como
tal las cookies son parte de dicho protocolo.
"""


# standard imports
from http.cookies import BaseCookie

# 3rd party imports
import logging
from fluidasserts import show_close
from fluidasserts import show_open

# local imports
from fluidasserts.helper import http_helper

logger = logging.getLogger('FLUIDAsserts')


def has_not_http_only(url, cookie_name):
    """Verifica si la cookie tiene el atributo httponly."""
    http_req = http_helper.HTTPSession(url)
    cookielist = BaseCookie(http_req.headers['set-cookie'])
    result = show_open()
    if cookie_name in cookielist:
        if cookielist[cookie_name]['httponly']:
            result = show_close()
        logger.info('%s HTTP cookie %s, Details=%s, %s',
                    cookie_name, url, cookielist[cookie_name], result)
    else:
        logger.info('%s HTTP cookie %s, Details=%s, %s',
                    cookie_name, url, 'Not Present', show_open())
    return result == show_open()


def has_not_secure(url, cookie_name):
    """Verifica si la cookie tiene el atributo secure."""
    http_req = http_helper.HTTPSession(url)
    cookielist = BaseCookie(http_req.headers['set-cookie'])
    result = show_open()
    if cookie_name in cookielist:
        if cookielist[cookie_name]['secure']:
            result = show_close()
        logger.info('%s HTTP cookie %s, Details=%s, %s',
                    cookie_name, url, cookielist[cookie_name], result)
    else:
        logger.info('%s HTTP cookie %s, Details=%s, %s',
                    cookie_name, url, 'Not Present', show_open())
    return result == show_open()
