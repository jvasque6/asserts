# -*- coding: utf-8 -*-

"""FTP module.

This module allows to check FTP especific vulnerabilities
"""

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
def is_a_valid_user(ip_address, username, password, port=PORT):
    """Check if given credencials are valid in FTP service."""
    result = False
    try:
        ftp = FTP()
        ftp.connect(ip_address, port)
        ftp.login(username, password)
        ftp.quit()
        result = True
        show_open('FTP Authentication {}:{}'.format(ip_address, port),
                  details=dict(username=username, password=password))
    except error_perm:
        show_close('FTP Authentication {}:{}'.format(ip_address, port),
                   details=dict(username=username, password=password))
        result = False
    return result


@track
def user_without_password(ip_address, username):
    """Check if a user can login without password."""
    return is_a_valid_user(ip_address, username, password=NULL_PASSWORD)


@track
def is_anonymous_enabled(ip_address):
    """Check if FTP service allows anonymous login."""
    return is_a_valid_user(ip_address, ANONYMOUS_USERNAME, ANONYMOUS_PASS)


@track
def is_admin_enabled(ip_address, password, username=ADMIN_USERNAME):
    """Check if FTP service allows admin login."""
    return is_a_valid_user(ip_address, username, password)


@track
def is_version_visible(ip_address, port=PORT):
    """Check if banner is visible."""
    service = banner_helper.FTPService(port)
    version = service.get_version(ip_address)

    result = True
    if version:
        result = True
        show_open('FTP version visible on {}:{}'.
                  format(ip_address, port),
                  details=dict(version=version))
    else:
        result = False
        show_close('FTP version not visible on {}:{}'.
                   format(ip_address, port))
    return result
