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


def has_not_http_only(cookie_name, url, cookie_jar, *args, **kwargs):
    """Checks if the cookie has the httponly attribute"""
    if url is None and cookie_jar is None:
        show_unknown('Cookie HttpOnly check for "{}"'.format(cookie_name),
                     details=dict(url=url, cookie_jar=cookie_jar))
        return True
    fingerprint = None
    if url is not None:
        sess = http_helper.HTTPSession(url, *args, **kwargs)
        cookielist = sess.cookies
        fingerprint = sess.get_fingerprint()
    else:
        cookielist = cookie_jar
    if cookielist is None:
        show_unknown('{} Cookies not present'.format(cookie_name),
                     details=dict(url=url, cookie_jar=cookie_jar,
                                  fingerprint=fingerprint))
        return True
    for cookie in cookielist:
        if cookie.name == cookie_name:
            if cookie.has_nonstandard_attr('HttpOnly') or \
               cookie.has_nonstandard_attr('httponly'):
                show_close('Cookie HttpOnly check for "{}"'.
                           format(cookie_name),
                           details=dict(url=url, cookie_jar=cookie_jar,
                                        fingerprint=fingerprint))
                result = False
            else:
                show_open('Cookie HttpOnly check for "{}"'.format(cookie_name),
                          details=dict(url=url, cookie_jar=cookie_jar,
                                       fingerprint=fingerprint))
                result = True
            return result
    show_unknown('Cookie "{}" not found'.format(cookie_name),
                 details=dict(url=url, cookie_jar=cookie_jar,
                              fingerprint=fingerprint))
    return True


def has_not_secure(cookie_name, url, cookie_jar, *args, **kwargs):
    """Checks if the cookie has the secure attribute"""
    if url is None and cookie_jar is None:
        show_unknown('Cookie Secure check for "{}"'.format(cookie_name),
                     details=dict(url=url, cookie_jar=cookie_jar))
        return True
    fingerprint = None
    if url is not None:
        sess = http_helper.HTTPSession(url, *args, **kwargs)
        cookielist = sess.cookies
        fingerprint = sess.get_fingerprint()
    else:
        cookielist = cookie_jar
    if cookielist is None:
        show_unknown('{} Cookies not present'.format(cookie_name),
                     details=dict(url=url, cookie_jar=cookie_jar,
                                  fingerprint=fingerprint))
        return True
    for cookie in cookielist:
        if cookie.name == cookie_name:
            if cookie.secure:
                show_close('Cookie Secure check for "{}"'.format(cookie_name),
                           details=dict(url=url, cookie_jar=cookie_jar,
                                        fingerprint=fingerprint))
                result = False
            else:
                show_open('Cookie Secure check for "{}"'.format(cookie_name),
                          details=dict(url=url, cookie_jar=cookie_jar,
                                       fingerprint=fingerprint))
                result = True
            return result
    show_unknown('Cookie "{}" not found'.format(cookie_name),
                 details=dict(url=url, cookie_jar=cookie_jar,
                              fingerprint=fingerprint))
    return True


@track
def has_not_httponly_set(cookie_name, url, *args, **kwargs):
    """Checks if the cookie has the httponly attribute"""
    return has_not_http_only(cookie_name, url, None, *args, **kwargs)


@track
def has_not_httponly_in_cookiejar(cookie_name, cookie_jar, *args, **kwargs):
    """Checks if the cookie has the httponly attribute"""
    return has_not_http_only(cookie_name, None, cookie_jar,
                             *args, **kwargs)


@track
def has_not_secure_set(cookie_name, url, *args, **kwargs):
    """Checks if the cookie has the secure attribute"""
    return has_not_secure(cookie_name, url, None, *args, **kwargs)


@track
def has_not_secure_in_cookiejar(cookie_name, cookie_jar, *args, **kwargs):
    """Checks if the cookie has the secure attribute"""
    return has_not_secure(cookie_name, None, cookie_jar,
                          *args, **kwargs)
