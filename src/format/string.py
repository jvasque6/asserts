# -*- coding: utf-8 -*-
"""Strings check module."""

# standard imports
import logging

# 3rd party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open

logger = logging.getLogger('FLUIDAsserts')


def __check_password_strength(password, length):
    """Function to check if a user password is secure."""
    dictionary = 'static/wordlists/password.lst'

    caps = sum(1 for c in password if c.isupper())
    lower = sum(1 for c in password if c.islower())
    nums = sum(1 for c in password if c.isdigit())
    special = sum(1 for c in password if not c.isalnum())

    with open(dictionary) as dict_fd:
        words = [x.rstrip() for x in dict_fd.readlines()]

    result = True

    if len(password) < length:
        logger.info('%s: %s is too short. Details=%s',
                    show_open(), password, len(password))
        result = True
    elif caps < 1 or lower < 1 or nums < 1 or special < 1:
        logger.info('%s: %s is too weak. Details=%s',
                    show_open(), password, "Caps: " + str(caps) +
                    " Lower: " + str(lower) +
                    " Numbers: " + str(nums) +
                    " Special: " + str(special))
        result = True
    elif password in words:
        logger.info('%s: %s is a dictionary password',
                    show_open(), password)
        result = True
    else:
        logger.info('%s: %s password is secure. Details=%s',
                    show_close(), password, "Caps: " + str(caps) +
                    " Lower: " + str(lower) +
                    " Numbers: " + str(nums) +
                    " Special: " + str(special))
        result = False

    return result


def is_user_password_insecure(password):
    """Function to check if a user password is secure."""
    min_password_len = 8

    return __check_password_strength(password, min_password_len)


def is_system_password_insecure(password):
    """Function to check if a system password is secure."""
    min_password_len = 20

    return __check_password_strength(password, min_password_len)


def is_otp_token_insecure(password):
    """Function to check if a system password is secure."""
    min_password_len = 6

    result = True
    if len(password) < min_password_len:
        logger.info('%s: %s OTP token is too short. Details=%s',
                    show_open(), password, len(password))
        result = True
    else:
        logger.info('%s: %s OTP token is secure. Details=%s',
                    show_close(), password, len(password))
        result = False

    return result


def is_ssid_insecure(ssid):
    """Function to check if a given SSID is secure."""
    dictionary = 'static/wordlists/password.lst'

    with open(dictionary) as dict_fd:
        words = [x.rstrip() for x in dict_fd.readlines()]

    result = True
    if ssid in words:
        logger.info('%s: %s is a dictionary password.',
                    show_open(), ssid)
        result = True
    else:
        logger.info('%s: %s is a secure SSID.',
                    show_close(), ssid)
        result = False

    return result
