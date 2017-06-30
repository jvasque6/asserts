# -*- coding: utf-8 -*-

"""Modulo para verificacion del protocolo SMTP.

Este modulo permite verificar vulnerabilidades propias de SMTP como:

    * Comando VRFY activo,
"""

# standard imports
import logging
import smtplib

# 3rd party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track

PORT = 25

logger = logging.getLogger('FLUIDAsserts')


@track
def has_vrfy(ip_address, port=PORT):
    """Tiene habilitado comando VRFY."""
    server = smtplib.SMTP(ip_address, port)
    vrfy = server.verify('root')

    result = True
    if 502 not in vrfy:
        logger.info('%s: SMTP "VRFY" method, Details=%s',
                    show_open(), ip_address + ':' + str(port))
        result = True
    else:
        logger.info('%s: SMTP "VRFY" method, Details=%s',
                    show_close(), ip_address + ':' + str(port))
        result = False

    server.quit()
    return result
