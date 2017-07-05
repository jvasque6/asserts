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

logger = logging.getLogger('FLUIDAsserts')

@track
def has_not_http_only(cookie_jar, cookie_name):
    """Verifica si la cookie tiene el atributo httponly."""
    result = show_unknown()
    for cookie in cookie_jar:
        if cookie.name == cookie_name:
            if cookie.has_nonstandard_attr('httponly'):
                result = show_close()
            else:
                result = show_open()
    logger.info('%s: Cookie check for "%s", Details=%s', result,
                cookie_name, 'HttpOnly')
    return result == show_open()

@track
def has_not_secure(cookie_jar, cookie_name):
    """Verifica si la cookie tiene el atributo secure."""
    result = show_unknown()
    for cookie in cookie_jar:
        if cookie.name == cookie_name:
            if cookie.secure:
                result = show_close()
            else:
                result = show_open()
    logger.info('%s: Cookie check for "%s", Details=%s', result,
                cookie_name, 'Secure')
    return result == show_open()
