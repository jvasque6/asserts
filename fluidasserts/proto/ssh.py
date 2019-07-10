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
from fluidasserts.helper import banner
from fluidasserts.helper import ssh
from fluidasserts.utils.decorators import track, level, notify

PORT = 22


@notify
@level('medium')
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
        service = banner.SSHService(port)
        fingerprint = service.get_fingerprint(host)
        with ssh.build_ssh_object() as ssh_obj:
            ssh_obj.connect(host, port, username=username, password=password)
            transport = ssh_obj.get_transport()
    except (paramiko.ssh_exception.NoValidConnectionsError,
            socket.timeout) as exc:
        show_unknown('Port closed',
                     details=dict(host=host,
                                  port=port,
                                  error=str(exc)))
        return False
    except paramiko.ssh_exception.AuthenticationException:
        show_close('SSH does not have insecure HMAC encryption algorithms',
                   details=dict(host=host, port=port, fingerprint=fingerprint))
        return False
    else:
        if "-cbc" not in transport.remote_cipher:
            show_close('SSH does not have insecure CBC encryption algorithms',
                       details=dict(host=host,
                                    port=port,
                                    remote_cipher=transport.remote_cipher,
                                    fingerprint=fingerprint))
            result = False
        else:
            show_open('SSH has insecure CBC encryption algorithms',
                      details=dict(host=host,
                                   port=port,
                                   remote_cipher=transport.remote_cipher,
                                   fingerprint=fingerprint))
            result = True

    return result


@notify
@level('medium')
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
        service = banner.SSHService(port)
        fingerprint = service.get_fingerprint(host)
        with ssh.build_ssh_object() as ssh_obj:
            ssh_obj.connect(host, port, username=username, password=password)
            transport = ssh_obj.get_transport()
    except (paramiko.ssh_exception.NoValidConnectionsError,
            socket.timeout) as exc:
        show_unknown('Port closed',
                     details=dict(host=host,
                                  port=port,
                                  error=str(exc)))
        return False
    except paramiko.ssh_exception.AuthenticationException:
        show_close('SSH does not have insecure HMAC encryption algorithms',
                   details=dict(host=host, port=port, fingerprint=fingerprint))
        return False
    else:
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


@notify
@level('low')
@track
def is_version_visible(ip_address: str, port: int = PORT) -> bool:
    """
    Check if banner is visible.

    :param ip_address: IP address to test.
    :param port: If necessary, specify port to connect to (default: 22).
    """
    service = banner.SSHService(port)
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
