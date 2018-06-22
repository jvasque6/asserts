# -*- coding: utf-8 -*-

"""This module allows to check SSH vulnerabilities."""

# standard imports
from __future__ import absolute_import
import socket

# 3rd party imports
import paramiko

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.helper import banner_helper
from fluidasserts.helper import ssh_helper
from fluidasserts.utils.decorators import track

PORT = 22


@track
def is_cbc_used(host: str, port: int = PORT, username: str = None,
                password: str = None) -> bool:
    """
    Check if SSH has CBC algorithms enabled.

    :param host: Address to test.
    :param port: If necessary, specify port to connect to.
    :param username: Username.
    :param password: Password.
    """
    result = True
    try:
        service = banner_helper.SSHService(port)
        fingerprint = service.get_fingerprint(host)
        ssh = ssh_helper.build_ssh_object()
        ssh.connect(host, port, username=username, password=password)
        transport = ssh.get_transport()

        if "-cbc" not in transport.remote_cipher:
            show_close('SSH does not have insecure CBC encription algorithms',
                       details=dict(host=host,
                                    port=port,
                                    remote_cipher=transport.remote_cipher,
                                    fingerprint=fingerprint))
            result = False
        else:
            show_open('SSH has insecure CBC encription algorithms',
                      details=dict(host=host,
                                   port=port,
                                   remote_cipher=transport.remote_cipher,
                                   fingerprint=fingerprint))
            result = True

        return result
    except socket.timeout as exc:
        show_unknown('Port closed',
                     details=dict(host=host,
                                  port=port,
                                  error=str(exc)))
        return False
    except paramiko.ssh_exception.AuthenticationException:
        show_close('SSH does not have insecure HMAC encryption algorithms',
                   details=dict(host=host, port=port, fingerprint=fingerprint))
        return False


@track
def is_hmac_used(host: str, port: int = PORT, username: str = None,
                 password: str = None) -> bool:
    """
    Check if SSH has weak HMAC algorithms enabled.

    :param host: Address to test.
    :param port: If necessary, specify port to connect to.
    :param username: Username.
    :param password: Password.
    """
    result = True
    try:
        service = banner_helper.SSHService(port)
        fingerprint = service.get_fingerprint(host)
        ssh = ssh_helper.build_ssh_object()
        ssh.connect(host, port, username=username, password=password)
        transport = ssh.get_transport()

        if "hmac-md5" not in transport.remote_cipher:
            show_close('SSH does not have insecure HMAC encryption algorithms',
                       details=dict(host=host,
                                    port=port,
                                    remote_cipher=transport.remote_cipher,
                                    fingerprint=fingerprint))
            result = False
        else:
            show_open('SSH has insecure HMAC encryption algorithms',
                      details=dict(host=host,
                                   port=port,
                                   remote_cipher=transport.remote_cipher,
                                   fingerprint=fingerprint))
            result = True

        return result
    except socket.timeout as exc:
        show_unknown('Port closed',
                     details=dict(host=host,
                                  port=port,
                                  error=str(exc)))
        return False
    except paramiko.ssh_exception.AuthenticationException:
        show_close('SSH does not have insecure HMAC encryption algorithms',
                   details=dict(host=host, port=port, fingerprint=fingerprint))
        return False


@track
def is_version_visible(ip_address: str, port: int = PORT) -> bool:
    """
    Check if banner is visible.

    :param ip_address: IP address to test.
    :param port: If necessary, specify port to connect to (default: 22).
    """
    service = banner_helper.SSHService(port)
    version = service.get_version(ip_address)
    fingerprint = service.get_fingerprint(ip_address)

    result = True
    if version:
        result = True
        show_open('SSH version visible on {}:{}'.format(ip_address, port),
                  details=dict(version=version,
                               fingerprint=fingerprint))
    else:
        result = False
        show_close('SSH version not visible on {}:{}'.
                   format(ip_address, port),
                   details=dict(fingerprint=fingerprint))
    return result
