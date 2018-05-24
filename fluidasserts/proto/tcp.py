# -*- coding: utf-8 -*-

"""
TCP module.

This module allows to check TCP-specific vulnerabilities.
"""

# standard imports
import socket
import ssl

# third party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track


@track
def is_port_open(ipaddress: str, port: int) -> bool:
    """
    Check if a given port on an IP address is open.

    :param ipaddress: IP address to test.
    :param port: Port to connect to.
    """
    assert 1 <= port <= 65535
    result = True
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ipaddress, port))
    except socket.error:
        show_close('Port is close', details=dict(ip=ipaddress, port=port))
        return False
    if result == 0:
        show_open('Port is open', details=dict(ip=ipaddress, port=port))
        result = True
    else:
        result = False
        show_close('Port is close', details=dict(ip=ipaddress, port=port))
    return result


@track
def is_port_insecure(ipaddress: str, port: int) -> bool:
    """
    Check if a given port on an IP address is insecure.

    :param ipaddress: IP address to test.
    :param port: Port to connect to.
    """
    assert 1 <= port <= 65535
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        ssl_sock = ssl.wrap_socket(sock)
        ssl_sock.connect_ex((ipaddress, port))
        show_close('Port is secure', details=dict(ip=ipaddress, port=port))
        return False
    except ssl.SSLError:
        show_open('Port is not secure', details=dict(ip=ipaddress, port=port))
        return True
