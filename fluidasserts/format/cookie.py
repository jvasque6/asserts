# -*- coding: utf-8 -*-

"""
HTTP Cookie module.

This module allows to check Cookies vulnerabilities.
"""


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


def _has_not_http_only(cookie_name: str, url: str, cookie_jar: dict,
                       *args, **kwargs) -> bool:
    r"""
    Check if a cookie has the ``httponly`` attribute.

    :param cookie_name: Name of the cookie to test.
    Exactly one of the following has to be ``None``.
    :param url: URL to get cookies.
    :param cookie_jar: Dict-like collection of cookies
                       as returned by ``requests.cookies``.
    :param \*args: Optional positional arguments for
                   :class:`~fluidasserts.helper.http_helper.HTTPSession`.
    :param \*\*kwargs: Optional keyword arguments for
                       :class:`~fluidasserts.helper.http_helper.HTTPSession`.
    """
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


def _has_not_secure(cookie_name: str, url: str, cookie_jar: dict,
                    *args, **kwargs) -> bool:
    r"""
    Check if a cookie has the ``secure`` attribute.

    :param cookie_name: Name of the cookie to test.
    Exactly one of the following has to be ``None``.
    :param url: URL to get cookies.
    :param cookie_jar: Dict-like collection of cookies
                       as returned by ``requests.cookies``.
    :param \*args: Optional positional arguments for
                   :class:`~fluidasserts.helper.http_helper.HTTPSession`.
    :param \*\*kwargs: Optional keyword arguments for
                       :class:`~fluidasserts.helper.http_helper.HTTPSession`.
    """
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
def has_not_httponly_set(cookie_name: str, url: str, *args, **kwargs) -> bool:
    r"""
    Check if the cookie in the ``url`` has the ``httponly`` attribute.

    :param cookie_name: Name of the cookie to test.
    :param url: URL to get cookies.
    :param \*args: Optional positional arguments for
                   :class:`~fluidasserts.helper.http_helper.HTTPSession`.
    :param \*\*kwargs: Optional keyword arguments for
                       :class:`~fluidasserts.helper.http_helper.HTTPSession`.
    """
    return _has_not_http_only(cookie_name, url, None, *args, **kwargs)


@track
def has_not_httponly_in_cookiejar(cookie_name: str, cookie_jar: dict,
                                  *args, **kwargs) -> bool:
    r"""
    Check if the cookie in the ``cookie_jar`` has the ``httponly`` attribute.

    :param cookie_name: Name of the cookie to test.
    :param cookie_jar: Dict-like collection of cookies
                       as returned by ``requests.cookies``.
    :param \*args: Optional positional arguments for
                   :class:`~fluidasserts.helper.http_helper.HTTPSession`.
    :param \*\*kwargs: Optional keyword arguments for
                       :class:`~fluidasserts.helper.http_helper.HTTPSession`.
    """
    return _has_not_http_only(cookie_name, None, cookie_jar,
                              *args, **kwargs)


@track
def has_not_secure_set(cookie_name: str, url: str, *args, **kwargs) -> bool:
    r"""
    Check if the cookie in the ``url`` has the ``secure`` attribute.

    :param cookie_name: Name of the cookie to test.
    :param url: URL to get cookies.
    :param \*args: Optional positional arguments for
                   :class:`~fluidasserts.helper.http_helper.HTTPSession`.
    :param \*\*kwargs: Optional keyword arguments for
                       :class:`~fluidasserts.helper.http_helper.HTTPSession`.
    """
    return _has_not_secure(cookie_name, url, None, *args, **kwargs)


@track
def has_not_secure_in_cookiejar(cookie_name: str, cookie_jar: dict,
                                *args, **kwargs) -> bool:
    r"""
    Check if the cookie in the ``cookie_jar`` has the ``secure`` attribute.

    :param cookie_name: Name of the cookie to test.
    :param cookie_jar: Dict-like collection of cookies
                       as returned by ``requests.cookies``.
    :param \*args: Optional positional arguments for
                   :class:`~fluidasserts.helper.http_helper.HTTPSession`.
    :param \*\*kwargs: Optional keyword arguments for
                       :class:`~fluidasserts.helper.http_helper.HTTPSession`.
    """
    return _has_not_secure(cookie_name, None, cookie_jar,
                           *args, **kwargs)
