# -*- coding: utf-8 -*-

""""This module allows to check FTP-specific vulnerabilities."""

# standard imports
from ftplib import error_perm
from ftplib import FTP

# 3rd party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.helper import banner_helper
from fluidasserts.utils.decorators import track

PORT = 21
NULL_PASSWORD = ''
ADMIN_USERNAME = 'root'
ANONYMOUS_USERNAME = 'anonymous'
ANONYMOUS_PASS = 'anonymous'


@track
def is_a_valid_user(ip_address: str, username: str,
                    password: str, port: int = PORT) -> bool:
    """
    Check if given credentials are valid in FTP service.

    :param ip_address: IP address to connect to.
    :param username: Username to check.
    :param password: Password to check.
    :param port: If necessary, specifiy port to connect to.
    """
    service = banner_helper.FTPService(port)
    fingerprint = service.get_fingerprint(ip_address)
    result = False
    try:
        ftp = FTP()
        ftp.connect(ip_address, port)
        ftp.login(username, password)
        ftp.quit()
        result = True
        show_open('FTP Authentication {}:{}'.format(ip_address, port),
                  details=dict(username=username, password=password,
                               fingerprint=fingerprint))
    except error_perm:
        show_close('FTP Authentication {}:{}'.format(ip_address, port),
                   details=dict(username=username, password=password,
                                fingerprint=fingerprint))
        result = False
    return result


@track
def user_without_password(ip_address: str, username: str) -> bool:
    """
    Check if a user can login without password.

    :param ip_address: IP address to connect to.
    :param username: Username to check.
    """
    return is_a_valid_user(ip_address, username, password=NULL_PASSWORD)


@track
def is_anonymous_enabled(ip_address: str) -> bool:
    """
    Check if FTP service allows anonymous login.

    :param ip_address: IP address to connect to.
    """
    return is_a_valid_user(ip_address, ANONYMOUS_USERNAME, ANONYMOUS_PASS)


@track
def is_admin_enabled(ip_address: str, password: str,
                     username: str = ADMIN_USERNAME) -> bool:
    """
    Check if FTP service allows admin login.

    :param ip_address: IP address to connect to.
    :param username: Username to check.
    :param password: Password to check.
    """
    return is_a_valid_user(ip_address, username, password)


@track
def is_version_visible(ip_address: str, port: int = PORT) -> bool:
    """
    Check if banner is visible.

    :param ip_address: IP address to connect to.
    :param port: If necessary, specifiy port to connect to.
    """
    service = banner_helper.FTPService(port)
    version = service.get_version(ip_address)
    fingerprint = service.get_fingerprint(ip_address)

    result = True
    if version:
        result = True
        show_open('FTP version visible on {}:{}'.
                  format(ip_address, port),
                  details=dict(version=version,
                               fingerprint=fingerprint))
    else:
        result = False
        show_close('FTP version not visible on {}:{}'.
                   format(ip_address, port),
                   details=dict(fingerprint=fingerprint))
    return result
