# -*- coding: utf-8 -*-
"""SMB check module."""

# standard imports
from __future__ import absolute_import
import logging
import socket

# 3rd party imports
from smb import SMBConnection
from smb import *

# local imports
from fluidasserts import show_close
from fluidasserts import show_open

logger = logging.getLogger('FLUIDAsserts')


def __smb_connect(server=None, user=None, password=None,
                  domain='WORKGROUP'):
    """Returns a SMB connection handler."""
    try:
        client_machine_name = 'assertspc'
        conn = SMBConnection.SMBConnection(user, password,
            client_machine_name, server, domain=domain, use_ntlm_v2=True,
            is_direct_tcp=True)

        if conn.connect(server, 445):
            return conn
        return False
    except socket.error:
        return False


def has_dirlisting(share=None, *args, **kwargs):
    """Check if a SMB share has dirlisting."""
    conn = __smb_connect(*args, **kwargs)

    if not conn:
        logger.info('%s: Error while connecting, \
Details=%s\%s:%s', show_open('ERROR'), domain, user, server)

        return False

    try:
        sharedfiles = conn.listPath(share, '/')
        logger.info('%s: Directory listing is possible, \
Details=%s\%s:%s', show_open(), domain, user, server)

        return True
    except smb_structs.OperationFailure:
        logger.info('%s: Directory listing not possible, \
Details=%s\%s:%s', show_close(), domain, user, server)

        return False


def is_anonymous_enabled(server=None, domain='WORKGROUP'):
    """Check if a SMB share has dirlisting."""
    user = 'anonymous'
    password = ''
    conn = __smb_connect(server=server, user=user, password=password,
        domain=domain)

    if not conn:
        print('%s: Anonymous login not possible, \
Details=%s\%s:%s', show_close(), domain, user, server)

        return False
    print('%s: Anonymous login enabled, Details=%s\%s:%s',
        show_open(), domain, user, server)
    return True
