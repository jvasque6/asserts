# -*- coding: utf-8 -*-

"""Modulo para verificacion del protocolo SMTP.

Este modulo permite verificar vulnerabilidades propias de SMTP como:

    * Comando VRFY activo,
"""

# standard imports
import logging
import smtplib

# 3rd party imports
# none

# local imports
# none


def has_vrfy(ip_address, port):
    """Tiene habilitado comando VRFY."""
    server = smtplib.SMTP(ip_address, port)
    vrfy = server.verify('Admin')

    if str('250') in vrfy:
        logging.info('SMTP "VRFY" method, Details=%s, %s',
                     ip_address + ':' + str(port), 'OPEN')
    else:
        logging.info('SMTP "VRFY" method, Details=%s, %s',
                     ip_address + ':' + str(port), 'CLOSE')

    server.quit()
