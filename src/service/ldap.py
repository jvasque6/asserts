# -*- coding: utf-8 -*-
"""Modulo LDAP."""

# standard imports
import logging

# 3rd party imports
from ldap3 import Connection
from ldap3.core.exceptions import LDAPExceptionError
from ldap3 import Server

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track

PORT = 389
SSL_PORT = 636

LOGGER = logging.getLogger('FLUIDAsserts')


@track
def is_anonymous_bind_allowed(ldap_server, port=PORT):
    """Function is_anonymous_bind_allowed.

    Function to check whether anonymous binding is allowed on
    LDAP server
    """
    result = True

    try:
        server = Server(ldap_server)
        conn = Connection(server)
    except LDAPExceptionError:
        LOGGER.info('%s: LDAP anonymous bind failed, Details=%s:%s',
                    show_close(), server, port)
        return False
    finally:
        conn.unbind()

    if conn.bind() is True:
        LOGGER.info('%s: LDAP anonymous bind success, Details=%s:%s',
                    show_open(), server, port)
        result = True
    else:
        LOGGER.info('%s: LDAP anonymous bind failed, Details=%s:%s',
                    show_close(), server, port)
        result = False

    return result
