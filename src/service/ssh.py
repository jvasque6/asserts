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
def is_cbc_used(site, port=PORT, username=None, password=None):
    """Function to check whether ssh has CBC algorithms enabled"""
    result = True
    try:
        service = banner_helper.SSHService(port)
        fingerprint = service.get_fingerprint(site)
        ssh = ssh_helper.build_ssh_object()
        ssh.connect(site, port, username=username, password=password)
        transport = ssh.get_transport()
        sec_opt = transport.get_security_options()

        if "-cbc" not in ",".join(sec_opt.ciphers):
            show_close('SSH does not have insecure CBC encription algorithms',
                       details=dict(site=site, ciphers=sec_opt.ciphers,
                                    fingerprint=fingerprint))
            result = False
        else:
            show_open('SSH has insecure CBC encription algorithms',
                      details=dict(site=site, ciphers=sec_opt.ciphers,
                                   fingerprint=fingerprint))
            result = True

        return result
    except socket.timeout:
        show_unknown('Port closed', details=dict(site=site, port=port))
        return False
    except paramiko.ssh_exception.AuthenticationException:
        show_close('SSH does not have insecure HMAC encryption algorithms',
                   details=dict(site=site, digests=sec_opt.digests,
                                fingerprint=fingerprint))
        return False

@track
def is_hmac_used(site, port=PORT, username=None, password=None):
    """Function to check whether ssh has weak hmac algorithms enabled"""
    result = True
    try:
        service = banner_helper.SSHService(port)
        fingerprint = service.get_fingerprint(site)
        ssh = ssh_helper.build_ssh_object()
        ssh.connect(site, port, username=username, password=password)
        transport = ssh.get_transport()
        sec_opt = transport.get_security_options()

        if "hmac-md5" not in ",".join(sec_opt.digests):
            show_close('SSH does not have insecure HMAC encryption algorithms',
                       details=dict(site=site, digests=sec_opt.digests,
                                    fingerprint=fingerprint))
            result = False
        else:
            show_open('SSH has insecure HMAC encryption algorithms',
                      details=dict(site=site, digests=sec_opt.digests,
                                   fingerprint=fingerprint))
            result = True

        return result
    except socket.timeout:
        show_unknown('Port closed', details=dict(site=site, port=port))
        return False
    except paramiko.ssh_exception.AuthenticationException:
        show_close('SSH does not have insecure HMAC encryption algorithms',
                   details=dict(site=site, digests=sec_opt.digests,
                                fingerprint=fingerprint))
        return False
