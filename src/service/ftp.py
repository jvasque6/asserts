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
from fluidasserts import LOGGER
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
        LOGGER.info('%s: FTP Authentication %s:%s, Details=%s',
                    show_open(), ip_address, port,
                    username + ':' + password)
    except error_perm:
        LOGGER.info('%s: FTP Authentication %s:%s, Details=%s',
                    show_close(), ip_address, port,
                    username + ':' + password)
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
        LOGGER.info('%s: FTP version visible on %s:%s, Details=%s',
                    show_open(), ip_address, port, version)
    else:
        result = False
        LOGGER.info('%s: FTP version not visible on %s, Details=None',
                    show_close(), ip_address)
    return result
