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
from fluidasserts.helper import banner_helper

PORT = 25


@track
def has_vrfy(ip_address, port=PORT):
    """Has VRFY command enabled."""
    server = smtplib.SMTP(ip_address, port)
    service = banner_helper.SMTPService(port)
    fingerprint = service.get_fingerprint(ip_address)
    vrfy = server.verify('root')

    result = True
    if 502 not in vrfy:
        show_open('SMTP "VRFY" method', details=dict(ip=ip_address,
                                                     fingerprint=fingerprint,
                                                     port=port))
        result = True
    else:
        show_close('SMTP "VRFY" method', details=dict(ip=ip_address,
                                                      fingerprint=fingerprint,
                                                      port=port))
        result = False

    server.quit()
    return result


@track
def is_version_visible(ip_address, port=PORT):
    """Check if banner is visible."""
    service = banner_helper.SMTPService(port)
    version = service.get_version(ip_address)
    fingerprint = service.get_fingerprint(ip_address)

    result = True
    if version:
        result = True
        show_open('SMTP version visible on {}:{}'.format(ip_address, port),
                  details=dict(version=version,
                               fingerprint=fingerprint))
    else:
        result = False
        show_close('SMTP version not visible on {}:{}'.
                   format(ip_address, port),
                   details=dict(fingerprint=fingerprint))
    return result
