# -*- coding: utf-8 -*-
"""This module allows to check Password and other text vulnerabilities."""

# standard imports
import pkg_resources

# 3rd party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track, level


def _check_password_strength(password: str, length: int) -> bool:
    """
    Check if a user password is secure.

    A user password is considered secured if following criteria are met:

    - Password length must be at least the given parameter ``length``.
    - Password must contain at least one uppercase character,
      one lowercase character, one number and one special character.
    - Password must not be a typical dictionary word.

    :param password: String to be tested.
    :param length: Minimum accepted password length.
    :returns: False if all conditions are met (secure),
    True otherwise (insecure).
    """
    static_path = pkg_resources.resource_filename('fluidasserts', 'static/')
    dictionary = static_path + 'wordlists/password.lst'

    caps = sum(1 for c in password if c.isupper())
    lower = sum(1 for c in password if c.islower())
    nums = sum(1 for c in password if c.isdigit())
    special = sum(1 for c in password if not c.isalnum())

    with open(dictionary) as dict_fd:
        words = [x.rstrip() for x in dict_fd.readlines()]

    result = True

    if len(password) < length:
        show_open('{} is too short'.format(password),
                  details=dict(length=len(password)))
        result = True
    elif password in words:
        show_open('{} is a dictionary password'.format(password))
        result = True
    elif caps < 1 or lower < 1 or nums < 1 or special < 1:
        show_open('{} is too weak'.format(password),
                  details=dict(caps=str(caps), lower=str(lower),
                               numbers=str(nums), special=str(special)))
        result = True
    else:
        show_close('{} password is secure'.format(password),
                   details=dict(caps=str(caps), lower=str(lower),
                                numbers=str(nums), special=str(special)))
        result = False

    return result


@level('high')
@track
def is_user_password_insecure(password: str) -> bool:
    """
    Check if a user password is insecure.

    A user password is considered secure if it is at least
    8 characters long and satisfies all other password criteria.

    :param password: Password to be tested.
    :returns: True if password insecure, False if secure.
    """
    min_password_len = 8

    return _check_password_strength(password, min_password_len)


@level('high')
@track
def is_system_password_insecure(password: str) -> bool:
    """
    Check if a system password is insecure.

    A system password is considered secure if it is at least
    20 characters long and satisfies all other password criteria.

    :param password: Password to be tested.
    :returns: True if password insecure, False if secure.
    """
    min_password_len = 20

    return _check_password_strength(password, min_password_len)


@level('medium')
@track
def is_otp_token_insecure(password: str) -> bool:
    """
    Check if a one-time password token is insecure.

    A one-time password token is considered secure if it is at least
    6 characters long.

    :param password: Password to be tested.
    :returns: True if insecure, False if secure.
    """
    min_password_len = 6

    result = True
    if len(password) < min_password_len:
        show_open('{} OTP token is too short'.format(password),
                  details=dict(length=len(password)))
        result = True
    else:
        show_close('{} OTP token is secure'.format(password),
                   details=dict(length=len(password)))
        result = False

    return result


@level('low')
@track
def is_ssid_insecure(ssid: str) -> bool:
    """
    Check if a given SSID is insecure.

    An SSID is considered secure if it is not a typical dictionary
    word such as "home" or "network".

    :param ssid: SSID to be tested.
    :returns: True if insecure, False if secure.
    """
    static_path = pkg_resources.resource_filename('fluidasserts', 'static/')
    dictionary = static_path + 'wordlists/password.lst'

    with open(dictionary) as dict_fd:
        words = [x.rstrip() for x in dict_fd.readlines()]

    result = True
    if ssid in words:
        show_open('{} is a dictionary word.'.format(ssid))
        result = True
    else:
        show_close('{} is a secure SSID.'.format(ssid))
        result = False

    return result
