# -*- coding: utf-8 -*-
"""
Strings check module
"""

# standard imports
import logging
import socket
import sys

# 3rd party imports
import datetime

# local imports
# None

#reload(sys)  
#sys.setdefaultencoding('utf8')

def __check_password_strength(password, length):
    """
    Function to check if a user password is secure
    """
    DICTIONARY = 'test/static/wordlists/password.lst'

    caps = sum(1 for c in password if c.isupper())
    lower = sum(1 for c in password if c.islower())
    nums = sum(1 for c in password if c.isdigit())
    special = sum(1 for c in password if not c.isalnum())

    fd = open(DICTIONARY)
    words = [x.rstrip() for x in fd.readlines()]

    result = True

    if len(password) < length:
        logging.info('%s is too short. Details=%s, %s',
                     password, len(password), 'OPEN')
        result = True
    elif caps < 1 or lower < 1 or nums < 1 or special < 1:
        logging.info('%s is too weak. Details=%s, %s',
                     password, "Caps: " + str(caps) +
                     "Lower: " + str(lower) +
                     "Numbers: " + str(nums) +
                     "Special: " + str(special), 'OPEN')
        result = True
    elif password in words:
        logging.info('%s is a dictionary password. Details=%s',
                     password, 'OPEN')
        result = True
    else:
        logging.info('%s password is secure. Details=%s, %s',
                     password, "Caps: " + str(caps) +
                     "Lower: " + str(lower) +
                     "Numbers: " + str(nums) +
                     "Special: " + str(special), 'OPEN')
        result = False

    return result


def is_user_password_insecure(password):
    """
    Function to check if a user password is secure
    """
    MIN_PASSWORD_LEN = 8

    return __check_password_strength(password, MIN_PASSWORD_LEN)


def is_system_password_insecure(password):
    """
    Function to check if a system password is secure
    """
    MIN_PASSWORD_LEN = 20

    return __check_password_strength(password, MIN_PASSWORD_LEN)


def is_otp_token_insecure(password):
    """
    Function to check if a system password is secure
    """
    MIN_PASSWORD_LEN = 6

    result = True
    if len(password) < MIN_PASSWORD_LEN:
        logging.info('%s OTP token is too short. Details=%s, %s',
                     password, len(password), 'OPEN')
        result = True
    else:
        logging.info('%s OTP token is secure. Details=%s, %s',
                     password, len(password), 'OPEN')
        result = False

    return result


def is_ssid_insecure(ssid):
    """
    Function to check if a given SSID is secure
    """
    DICTIONARY = 'test/static/wordlists/password.lst'
     
    fd = open(DICTIONARY)
    words = [x.rstrip() for x in fd.readlines()]

    result = True
    if ssid in words:
        logging.info('%s is a dictionary password. Details=%s',
                     ssid, 'OPEN')
        result = True
    else:
        logging.info('%s is a secure SSID. Details=%s',
                     ssid, 'CLOSE')
        result = False

    return result


def is_event_not_compliant(event):
    """
    Function to check whether a given event is compliant
    """
    pass
