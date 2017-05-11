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

PORT = 25

logger = logging.getLogger('FLUIDAsserts')


def has_vrfy(ip_address, port=PORT):
    """Tiene habilitado comando VRFY."""
    server = smtplib.SMTP(ip_address, port)
    vrfy = server.verify('root')

    result = True
    if 502 not in vrfy:
        logger.info('SMTP "VRFY" method, Details=%s, %s',
                    ip_address + ':' + str(port), show_open())
        result = True
    else:
        logger.info('SMTP "VRFY" method, Details=%s, %s',
                    ip_address + ':' + str(port), show_close())
        result = False

    server.quit()
    return result
