# -*- coding: utf-8 -*-
"""SSH module."""

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
def is_cbc_used(host, port=PORT, username=None, password=None):
    """Function to check whether ssh has CBC algorithms enabled"""
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
                                    remote_cipher=transport.remote_cipher,
                                    fingerprint=fingerprint))
            result = False
        else:
            show_open('SSH has insecure CBC encription algorithms',
                      details=dict(host=host,
                                   remote_cipher=transport.remote_cipher,
                                   fingerprint=fingerprint))
            result = True

        return result
    except socket.timeout:
        show_unknown('Port closed', details=dict(host=host, port=port))
        return False
    except paramiko.ssh_exception.AuthenticationException:
        show_close('SSH does not have insecure HMAC encryption algorithms',
                   details=dict(host=host, fingerprint=fingerprint))
        return False


@track
def is_hmac_used(host, port=PORT, username=None, password=None):
    """Function to check whether ssh has weak hmac algorithms enabled"""
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
                                    remote_cipher=transport.remote_cipher,
                                    fingerprint=fingerprint))
            result = False
        else:
            show_open('SSH has insecure HMAC encryption algorithms',
                      details=dict(host=host,
                                   remote_cipher=transport.remote_cipher,
                                   fingerprint=fingerprint))
            result = True

        return result
    except socket.timeout:
        show_unknown('Port closed', details=dict(host=host, port=port))
        return False
    except paramiko.ssh_exception.AuthenticationException:
        show_close('SSH does not have insecure HMAC encryption algorithms',
                   details=dict(host=host, fingerprint=fingerprint))
        return False
