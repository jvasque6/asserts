# -*- coding: utf-8 -*-

"""Modulo para verificacion del protocolo TCP.

Este modulo permite verificar vulnerabilidades propias de TCP como:

    * El puerto se encuentra abierto
"""

# standard imports
import logging
import socket

# third party imports
from termcolor import colored

# local imports
# none

logger = logging.getLogger('FLUIDAsserts')


def is_port_open(ipaddress, port):
    """Check if a given port on an IP address is open."""
    status = colored('CLOSE', 'green')
    result = True
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        result = sock.connect_ex((ipaddress, port))
    except socket.error:
        result = False
        status = colored('CLOSE', 'green')
    if result == 0:
        status = colored('OPEN', 'red')
        result = True
    else:
        result = False
    sock.close()
    logger.info('Checking port, Details=%s, %s',
                ipaddress + ':' + str(port), status)
    return result
