# -*- coding: utf-8 -*-

"""SMTP module.

This module allows to check SMTP especific vulnerabilities
"""

# standard imports
import smtplib

# 3rd party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track
from fluidasserts import LOGGER
from fluidasserts.helper import banner_helper

PORT = 25


@track
def has_vrfy(ip_address, port=PORT):
    """Has VRFY command enabled."""
    server = smtplib.SMTP(ip_address, port)
    vrfy = server.verify('root')

    result = True
    if 502 not in vrfy:
        LOGGER.info('%s: SMTP "VRFY" method, Details=%s',
                    show_open(), ip_address + ':' + str(port))
        result = True
    else:
        LOGGER.info('%s: SMTP "VRFY" method, Details=%s',
                    show_close(), ip_address + ':' + str(port))
        result = False

    server.quit()
    return result


@track
def is_version_visible(ip_address, port=PORT):
    """Check if banner is visible."""
    service = banner_helper.SMTPService(port)
    banner = banner_helper.get_banner(service, ip_address)
    version = banner_helper.get_version(service, banner)

    result = True
    if version:
        result = True
        LOGGER.info('%s: SMTP version visible on %s:%s, Details=%s, %s',
                    show_open(), ip_address, port, banner, version)
    else:
        result = False
        LOGGER.info('%s: SMTP version not visible on %s, Details=None',
                    show_close(), ip_address)
    return result
