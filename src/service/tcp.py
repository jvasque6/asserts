# -*- coding: utf-8 -*-

"""TCP module.

This module allows to check TCP especific vulnerabilities
"""

# standard imports
from __future__ import absolute_import
import socket
import ssl

# third party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track


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
        show_close('Port is close, Details={}'.
                   format(ipaddress + ':' + str(port)))
    if result == 0:
        show_open('Port is open, Details={}'.
                  format(ipaddress + ':' + str(port)))
        result = True
    else:
        result = False
        show_close('Port is close, Details={}'.
                   format(ipaddress + ':' + str(port)))
    return result


@track
def is_port_insecure(ipaddress, port):
    """Check if a given port on an IP address is insecure."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        ssl_sock = ssl.wrap_socket(sock)
        ssl_sock.connect_ex((ipaddress, port))
        show_close('Port is secure, Details={}'.
                   format(ipaddress + ':' + str(port)))
        return False
    except ssl.SSLError:
        show_open('Port is not secure, Details={}'.
                  format(ipaddress + ':' + str(port)))
        return True
