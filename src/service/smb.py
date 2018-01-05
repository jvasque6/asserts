# -*- coding: utf-8 -*-
"""SMB check module."""

# standard imports
from __future__ import absolute_import
import logging
import socket

# 3rd party imports
from smb import SMBConnection
from smb import smb_structs

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track

LOGGER = logging.getLogger('FLUIDAsserts')


def __smb_connect(server=None, user=None, password=None,
                  domain='WORKGROUP'):
    """Returns a SMB connection handler."""
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
def has_dirlisting(share=None, *args, **kwargs):
    """Check if a SMB share has dirlisting."""
    conn = __smb_connect(*args, **kwargs)

    if not conn:
        LOGGER.info('%s: Error while connecting, \
Details=%s/%s:%s', show_open('ERROR'),
                    kwargs['domain'], kwargs['user'], kwargs['server'])

        return False

    try:
        conn.listPath(share, '/')
        LOGGER.info('%s: Directory listing is possible, \
Details=%s/%s:%s', show_open(),
                    kwargs['domain'], kwargs['user'], kwargs['server'])

        return True
    except smb_structs.OperationFailure:
        LOGGER.info('%s: Directory listing not possible, \
Details=%s/%s:%s', show_close(),
                    kwargs['domain'], kwargs['user'], kwargs['server'])

        return False


@track
def is_anonymous_enabled(server=None, domain='WORKGROUP'):
    """Check if a SMB share has dirlisting."""
    user = 'anonymous'
    password = ''
    conn = __smb_connect(server=server, user=user, password=password,
                         domain=domain)

    if not conn:
        LOGGER.info('%s: Anonymous login not possible, \
Details=%s/%s:%s', show_close(), domain, user, server)

        return False
    LOGGER.info('%s: Anonymous login enabled, Details=%s/%s:%s',
                show_open(), domain, user, server)
    return True
