# -*- coding: utf-8 -*-
"""Strings check module."""

# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track


def __check_password_strength(password, length):
    """Check if a user password is secure."""
    dictionary = 'static/wordlists/password.lst'

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
        show_open('{} password is secure'.format(password),
                  details=dict(caps=str(caps), lower=str(lower),
                               numbers=str(nums), special=str(special)))
        result = False

    return result


@track
def is_user_password_insecure(password):
    """Check if a user password is secure."""
    min_password_len = 8

    return __check_password_strength(password, min_password_len)


@track
def is_system_password_insecure(password):
    """Check if a system password is secure."""
    min_password_len = 20

    return __check_password_strength(password, min_password_len)


@track
def is_otp_token_insecure(password):
    """Check if a system password is secure."""
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


@track
def is_ssid_insecure(ssid):
    """Check if a given SSID is secure."""
    dictionary = 'static/wordlists/password.lst'

    with open(dictionary) as dict_fd:
        words = [x.rstrip() for x in dict_fd.readlines()]

    result = True
    if ssid in words:
        show_open('{} is a dictionary password.'.format(ssid))
        result = True
    else:
        show_close('{} is a secure SSID.'.format(ssid))
        result = False

    return result
