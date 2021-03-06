# -*- coding: utf-8 -*-

"""This module allows to check Cookies vulnerabilities."""


# standard imports
# None

# 3rd party imports
from typing import Optional

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.helper import http
from fluidasserts.utils.decorators import track, level, notify


def _has_not_http_only(cookie_name: str, url: Optional[str],
                       cookie_jar: Optional[dict], *args, **kwargs) -> bool:
    r"""
    Check if a cookie has the ``httponly`` attribute.

    :param cookie_name: Name of the cookie to test.
    Exactly one of the following has to be ``None``.
    :param url: URL to get cookies.
    :param cookie_jar: Dict-like collection of cookies
                       as returned by ``requests.cookies``.
    :param \*args: Optional positional arguments for
                   :class:`~fluidasserts.helper.http.HTTPSession`.
    :param \*\*kwargs: Optional keyword arguments for
                       :class:`~fluidasserts.helper.http.HTTPSession`.
    """
    fingerprint = None
    if url is not None:
        try:
            sess = http.HTTPSession(url, *args, **kwargs)
            cookielist = sess.cookies
            fingerprint = sess.get_fingerprint()
        except http.ConnError:
            show_unknown('Could not connect', details=dict(url=url))
            return False
    else:
        cookielist = cookie_jar
    if cookielist is None:
        show_unknown('{} Cookies not present'.format(cookie_name),
                     details=dict(url=url,
                                  fingerprint=fingerprint))
        return False
    for cookie in cookielist:
        if cookie.name == cookie_name:
            if cookie.has_nonstandard_attr('HttpOnly') or \
               cookie.has_nonstandard_attr('httponly'):
                show_close('Cookie HttpOnly check for "{}"'.
                           format(cookie_name),
                           details=dict(url=url,
                                        fingerprint=fingerprint))
                result = False
            else:
                show_open('Cookie HttpOnly check for "{}"'.format(cookie_name),
                          details=dict(url=url,
                                       fingerprint=fingerprint))
                result = True
            return result
    show_unknown('Cookie "{}" not found'.format(cookie_name),
                 details=dict(url=url,
                              fingerprint=fingerprint))
    return False


def _has_not_secure(cookie_name: str, url: Optional[str],
                    cookie_jar: Optional[dict], *args, **kwargs) -> bool:
    r"""
    Check if a cookie has the ``secure`` attribute.

    :param cookie_name: Name of the cookie to test.
    Exactly one of the following has to be ``None``.
    :param url: URL to get cookies.
    :param cookie_jar: Dict-like collection of cookies
                       as returned by ``requests.cookies``.
    :param \*args: Optional positional arguments for
                   :class:`~fluidasserts.helper.http.HTTPSession`.
    :param \*\*kwargs: Optional keyword arguments for
                       :class:`~fluidasserts.helper.http.HTTPSession`.
    """
    fingerprint = None
    if url is not None:
        try:
            sess = http.HTTPSession(url, *args, **kwargs)
            cookielist = sess.cookies
            fingerprint = sess.get_fingerprint()
        except http.ConnError:
            show_unknown('Could not connect', details=dict(url=url))
            return False
    else:
        cookielist = cookie_jar
    if cookielist is None:
        show_unknown('{} Cookies not present'.format(cookie_name),
                     details=dict(url=url,
                                  fingerprint=fingerprint))
        return False
    for cookie in cookielist:
        if cookie.name == cookie_name:
            if cookie.secure:
                show_close('Cookie Secure check for "{}"'.format(cookie_name),
                           details=dict(url=url,
                                        fingerprint=fingerprint))
                result = False
            else:
                show_open('Cookie Secure check for "{}"'.format(cookie_name),
                          details=dict(url=url,
                                       fingerprint=fingerprint))
                result = True
            return result
    show_unknown('Cookie "{}" not found'.format(cookie_name),
                 details=dict(url=url,
                              fingerprint=fingerprint))
    return False


def _has_not_same_site(cookie_name: str, url: Optional[str],
                       cookie_jar: Optional[dict], *args, **kwargs) -> bool:
    r"""
    Check if a cookie has the ``samesite`` attribute.

    :param cookie_name: Name of the cookie to test.
    Exactly one of the following has to be ``None``.
    :param url: URL to get cookies.
    :param cookie_jar: Dict-like collection of cookies
                       as returned by ``requests.cookies``.
    :param \*args: Optional positional arguments for
                   :class:`~fluidasserts.helper.http.HTTPSession`.
    :param \*\*kwargs: Optional keyword arguments for
                       :class:`~fluidasserts.helper.http.HTTPSession`.
    """
    fingerprint = None
    if url is not None:
        try:
            sess = http.HTTPSession(url, *args, **kwargs)
            cookielist = sess.cookies
            fingerprint = sess.get_fingerprint()
        except http.ConnError:
            show_unknown('Could not connect', details=dict(url=url))
            return False
    else:
        cookielist = cookie_jar
    if cookielist is None:
        show_unknown('{} Cookies not present'.format(cookie_name),
                     details=dict(url=url,
                                  fingerprint=fingerprint))
        return False
    for cookie in cookielist:
        if cookie.name == cookie_name:
            if cookie.has_nonstandard_attr('SameSite'):
                if cookie.get_nonstandard_attr('SameSite') == 'Strict':
                    show_close('SameSite is set to Strict',
                               details=dict(url=url,
                                            cookie=cookie_name,
                                            fingerprint=fingerprint))
                    return False
            show_open('Cookie SameSite not present or Lax',
                      details=dict(url=url, cookie=cookie_name,
                                   fingerprint=fingerprint))
            return True
    show_unknown('Cookie "{}" not found'.format(cookie_name),
                 details=dict(url=url,
                              fingerprint=fingerprint))
    return False


@notify
@level('medium')
@track
def has_not_httponly_set(cookie_name: str, url: str, *args, **kwargs) -> bool:
    r"""
    Check if the cookie in the ``url`` has the ``httponly`` attribute.

    :param cookie_name: Name of the cookie to test.
    :param url: URL to get cookies.
    :param \*args: Optional positional arguments for
                   :class:`~fluidasserts.helper.http.HTTPSession`.
    :param \*\*kwargs: Optional keyword arguments for
                       :class:`~fluidasserts.helper.http.HTTPSession`.
    """
    return _has_not_http_only(cookie_name, url, None, *args, **kwargs)


@notify
@level('medium')
@track
def has_not_httponly_in_cookiejar(cookie_name: str, cookie_jar: dict,
                                  *args, **kwargs) -> bool:
    r"""
    Check if the cookie in the ``cookie_jar`` has the ``httponly`` attribute.

    :param cookie_name: Name of the cookie to test.
    :param cookie_jar: Dict-like collection of cookies
                       as returned by ``requests.cookies``.
    :param \*args: Optional positional arguments for
                   :class:`~fluidasserts.helper.http.HTTPSession`.
    :param \*\*kwargs: Optional keyword arguments for
                       :class:`~fluidasserts.helper.http.HTTPSession`.
    """
    return _has_not_http_only(cookie_name, None, cookie_jar,
                              *args, **kwargs)


@notify
@level('medium')
@track
def has_not_secure_set(cookie_name: str, url: str, *args, **kwargs) -> bool:
    r"""
    Check if the cookie in the ``url`` has the ``secure`` attribute.

    :param cookie_name: Name of the cookie to test.
    :param url: URL to get cookies.
    :param \*args: Optional positional arguments for
                   :class:`~fluidasserts.helper.http.HTTPSession`.
    :param \*\*kwargs: Optional keyword arguments for
                       :class:`~fluidasserts.helper.http.HTTPSession`.
    """
    return _has_not_secure(cookie_name, url, None, *args, **kwargs)


@notify
@level('medium')
@track
def has_not_secure_in_cookiejar(cookie_name: str, cookie_jar: dict,
                                *args, **kwargs) -> bool:
    r"""
    Check if the cookie in the ``cookie_jar`` has the ``secure`` attribute.

    :param cookie_name: Name of the cookie to test.
    :param cookie_jar: Dict-like collection of cookies
                       as returned by ``requests.cookies``.
    :param \*args: Optional positional arguments for
                   :class:`~fluidasserts.helper.http.HTTPSession`.
    :param \*\*kwargs: Optional keyword arguments for
                       :class:`~fluidasserts.helper.http.HTTPSession`.
    """
    return _has_not_secure(cookie_name, None, cookie_jar,
                           *args, **kwargs)


@notify
@level('medium')
@track
def has_not_samesite_set(cookie_name: str, url: str, *args, **kwargs) -> bool:
    r"""
    Check if the cookie in the ``url`` has the ``samesite`` attribute.

    :param cookie_name: Name of the cookie to test.
    :param url: URL to get cookies.
    :param \*args: Optional positional arguments for
                   :class:`~fluidasserts.helper.http.HTTPSession`.
    :param \*\*kwargs: Optional keyword arguments for
                       :class:`~fluidasserts.helper.http.HTTPSession`.
    """
    return _has_not_same_site(cookie_name, url, None, *args, **kwargs)


@notify
@level('medium')
@track
def has_not_samesite_in_cookiejar(cookie_name: str, cookie_jar: dict,
                                  *args, **kwargs) -> bool:
    r"""
    Check if the cookie in the ``cookie_jar`` has the ``samesite`` attribute.

    :param cookie_name: Name of the cookie to test.
    :param cookie_jar: Dict-like collection of cookies
                       as returned by ``requests.cookies``.
    :param \*args: Optional positional arguments for
                   :class:`~fluidasserts.helper.http.HTTPSession`.
    :param \*\*kwargs: Optional keyword arguments for
                       :class:`~fluidasserts.helper.http.HTTPSession`.
    """
    return _has_not_same_site(cookie_name, None, cookie_jar,
                              *args, **kwargs)
