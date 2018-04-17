# -*- coding: utf-8 -*-
"""SMB check module."""

# standard imports
from __future__ import absolute_import
import socket

# 3rd party imports
from smb import SMBConnection
from smb import smb_structs

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track


def __smb_connect(server=None, user=None, password=None,
                  domain='WORKGROUP'):
    """Return a SMB connection handler."""
    try:
        client_machine_name = 'assertspc'
        conn = SMBConnection.SMBConnection(user, password,
                                           client_machine_name, server,
                                           domain=domain, use_ntlm_v2=True,
                                           is_direct_tcp=True)

        if conn.connect(server, port=445):
            return conn
        return False
    except socket.error:
        return False


@track
def has_dirlisting(share, *args, **kwargs):
    """Check if a SMB share has dirlisting."""
    conn = __smb_connect(*args, **kwargs)

    if not conn:
        show_unknown('Error while connecting',
                     details=dict(domain=kwargs['domain'],
                                  user=kwargs['user'],
                                  server=kwargs['server']))
        return False

    try:
        conn.listPath(share, '/')
        show_open('Directory listing is possible',
                  details=dict(domain=kwargs['domain'],
                               user=kwargs['user'],
                               server=kwargs['server']))

        return True
    except smb_structs.OperationFailure:
        show_close('Directory listing not possible',
                   details=dict(domain=kwargs['domain'],
                                user=kwargs['user'],
                                server=kwargs['server']))

        return False


@track
def is_anonymous_enabled(server=None, domain='WORKGROUP'):
    """Check if a SMB share has dirlisting."""
    user = 'anonymous'
    password = ''
    conn = __smb_connect(server=server, user=user, password=password,
                         domain=domain)

    if not conn:
        show_close('Anonymous login not possible',
                   details=dict(domain=domain, user=user, server=server))

        return False
    show_open('Anonymous login enabled',
              details=dict(domain=domain, user=user, server=server))
    return True
