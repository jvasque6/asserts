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
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track

logger = logging.getLogger('FLUIDAsserts')


@track
def is_port_open(ipaddress, port):
    """Check if a given port on an IP address is open."""
    result = True
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ipaddress, port))
    except socket.error:
        result = False
        logger.info('%s: Port is close, Details=%s',
                    show_close(), ipaddress + ':' + str(port))
    if result == 0:
        logger.info('%s: Port is open, Details=%s',
                    show_open(), ipaddress + ':' + str(port))
        result = True
    else:
        result = False
        logger.info('%s: Port is close, Details=%s',
                    show_close(), ipaddress + ':' + str(port))
    return result
