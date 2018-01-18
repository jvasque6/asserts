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
