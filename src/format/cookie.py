# -*- coding: utf-8 -*-

"""HTTP Cookie module."""


# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.helper import http_helper
from fluidasserts.utils.decorators import track


def __has_not_http_only(cookie_name, url=None, cookie_jar=None):
    """Verifica si la cookie tiene el atributo httponly."""
    if url is None and cookie_jar is None:
        show_unknown('Cookie check for "{}", Details={}'.
                     format(cookie_name, 'HttpOnly'))
        return True
    if url is not None:
        sess = http_helper.HTTPSession(url)
        cookielist = sess.cookies
    else:
        cookielist = cookie_jar
    if cookielist is None:
        show_unknown('{} Cookie not present'.format(cookie_name))
        return True
    for cookie in cookielist:
        if cookie.name == cookie_name:
            if cookie.has_nonstandard_attr('HttpOnly') or \
               cookie.has_nonstandard_attr('httponly'):
                show_close('Cookie check for "{}", Details={}'.
                           format(cookie_name, 'HttpOnly'))
                result = False
            else:
                show_open('Cookie check for "{}", Details={}'.
                          format(cookie_name, 'HttpOnly'))
                result = True
    return result


def __has_not_secure(cookie_name, url=None, cookie_jar=None):
    """Verifica si la cookie tiene el atributo secure."""
    if url is None and cookie_jar is None:
        show_unknown('Cookie check for "{}", Details={}'.
                     format(cookie_name, 'Secure'))
        return True
    if url is not None:
        sess = http_helper.HTTPSession(url)
        cookielist = sess.cookies
    else:
        cookielist = cookie_jar
    if cookielist is None:
        show_unknown('{} Cookie not present'.format(cookie_name))
        return True
    for cookie in cookielist:
        if cookie.name == cookie_name:
            if cookie.secure:
                show_close('Cookie check for "{}", Details={}'.
                           format(cookie_name, 'Secure'))
                result = False
            else:
                show_open('Cookie check for "{}", Details={}'.
                          format(cookie_name, 'Secure'))
                result = True
    return result


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
