# -*- coding: utf-8 -*-
"""
SMB check module.

This module allows to check SMB vulnerabilites.
"""

# standard imports
from __future__ import absolute_import
import socket
from typing import Optional, Union

# 3rd party imports
from smb import SMBConnection
from smb import smb_structs

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track


Typconn = SMBConnection.SMBConnection


def _smb_connect(server: Optional[str] = None,
                 user: Optional[str] = None,
                 password: Optional[str] = None,
                 domain: str = 'WORKGROUP') -> Union[Typconn, bool]:
    """
    Return an SMB connection handler.

    :param server: The NetBIOS machine name of the remote server.
    :param user: Username to authenticate SMB connection.
    :param password: Password for given user.
    :param domain: The network domain/workgroup. Defaults to 'WORKGROUP'
    :return: SMBConnection object if possible, otherwise False
    """
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
def has_dirlisting(share: str, *args, **kwargs) -> bool:
    r"""
    Check if an SMB share has dirlisting.

    :param share: The name of the shared folder.
    :param \*args: Optional arguments for SMB connect.
    :param \*\*kwargs: Optional arguments for SMB connection.
    """
    conn = _smb_connect(*args, **kwargs)

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
def is_anonymous_enabled(server: str = None,
                         domain: str = 'WORKGROUP') -> bool:
    """
    Check if anonymous login is possible over SMB.

    :param server: The NetBIOS machine name of the remote server.
    :param domain: The network domain/workgroup. Defaults to 'WORKGROUP'
    """
    user = 'anonymous'
    password = ''
    conn = _smb_connect(server=server, user=user, password=password,
                        domain=domain)

    if not conn:
        show_close('Anonymous login not possible',
                   details=dict(domain=domain, user=user, server=server))

        return False
    show_open('Anonymous login enabled',
              details=dict(domain=domain, user=user, server=server))
    return True
