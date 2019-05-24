# -*- coding: utf-8 -*-

"""This module allows to check SMTP-specific vulnerabilities."""

# standard imports
import smtplib

# 3rd party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track, level, notify
from fluidasserts.helper import banner

PORT = 25


@notify
@level('medium')
@track
def has_vrfy(ip_address: str, port: int = PORT) -> bool:
    """
    Check if IP has VRFY command enabled.

    :param ip_address: IP address to test.
    :param port: If necessary, specify port to connect to (default: 25).
    """
    server = smtplib.SMTP(ip_address, port)
    service = banner.SMTPService(port)
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


@notify
@level('low')
@track
def is_version_visible(ip_address: str, port: int = PORT,
                       payload: bool = None) -> bool:
    """
    Check if banner is visible.

    :param ip_address: IP address to test.
    :param port: If necessary, specify port to connect to (default: 25).
    """
    service = banner.SMTPService(port, payload=payload)
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
