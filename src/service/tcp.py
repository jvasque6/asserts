# -*- coding: utf-8 -*-

"""Modulo para verificacion del protocolo TCP.

Este modulo permite verificar vulnerabilidades propias de TCP como:

    * El puerto se encuentra abierto
"""

# standard imports
import logging
import socket

# third party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open

logger = logging.getLogger('FLUIDAsserts')


def is_port_open(ipaddress, port):
    """Check if a given port on an IP address is open."""
    result = True
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ipaddress, port))
    except socket.error:
        result = False
        logger.info('Port is close, Details=%s, %s',
                    ipaddress + ':' + str(port), show_close())
    if result == 0:
        logger.info('Port is open, Details=%s, %s',
                    ipaddress + ':' + str(port), show_open())
        result = True
    else:
        result = False
        logger.info('Port is close, Details=%s, %s',
                    ipaddress + ':' + str(port), show_close())
    return result
