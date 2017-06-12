# -*- coding: utf-8 -*-
"""SMB check module."""

# standard imports
from __future__ import absolute_import
import logging

# 3rd party imports
from smb import *
from SMBConnection import *

# local imports
from fluidasserts import show_close
from fluidasserts import show_open

logger = logging.getLogger('FLUIDAsserts')


def __smb_connect(server=server, user=user, password=password,
                  domain=domain):
    """Returns a SMB connection handler."""
    try:
        client_machine_name = 'assertspc'
        conn = SMBConnection(user password, client_machine_name, server,
            domain=domain, use_ntlm_v2=True, is_direct_tcp=True)

        return conn.connect(server, 445)
    except:
        return None


def has_dirlisting(share=share, *args, **kwargs):
    """Check if a SMB share has dirlisting."""
    conn = __smb_connect(*args, **kwargs)

    if conn is False:
        logger.info('%s: Directory listing not possible, \
Details=%s\%s:%s', show_close(), domain, user, server)

        return False

    sharedfiles = conn.listPath(share, '/')
    print (sharedfiles)


def is_anonymous_enabled(server=server, domain=domain):
    """Check if a SMB share has dirlisting."""
    user = 'anonymous'
    password = ''
    conn = __smb_connect(server=server, user=user, password=password,
        domain=domain)

    if conn is False:
        logger.info('%s: Anonymous login not possible, \
Details=%s\%s:%s', show_close(), domain, user, server)

        return False
    logger.info('%s: Anonymous login enabled, Details=%s\%s:%s',
        show_close(), domain, user, server)
    return True
