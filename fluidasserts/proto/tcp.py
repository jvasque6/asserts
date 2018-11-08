# -*- coding: utf-8 -*-

"""This module allows to check TCP-specific vulnerabilities."""

# standard imports
import ssl
import socket


# third party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.helper import ssl as ssl_helper
from fluidasserts.utils.decorators import track, level


@level('low')
@track
def is_port_open(ipaddress: str, port: int) -> bool:
    """
    Check if a given port on an IP address is open.

    :param ipaddress: IP address to test.
    :param port: Port to connect to.
    """
    assert 1 <= port <= 65535
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ipaddress, port))
        show_open('Port is open', details=dict(ip=ipaddress, port=port))
        return True
    except socket.error:
        show_close('Port is close', details=dict(ip=ipaddress, port=port))
        return False


@level('medium')
@track
def is_port_insecure(ipaddress: str, port: int) -> bool:
    """
    Check if a given port on an IP address is insecure.

    :param ipaddress: IP address to test.
    :param port: Port to connect to.
    """
    assert 1 <= port <= 65535
    try:
        with ssl_helper.connect_legacy(ipaddress, port):
            show_close('Port is secure', details=dict(ip=ipaddress, port=port))
            return False
    except (ConnectionRefusedError, socket.timeout):
        show_unknown('Could not connect',
                     details=dict(ip=ipaddress, port=port))
        return False
    except ssl.SSLError:
        show_open('Port is not secure', details=dict(ip=ipaddress, port=port))
        return True
