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

PORT = 389
SSL_PORT = 636

logger = logging.getLogger('FLUIDAsserts')


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
        logger.info('LDAP anonymous bind failed, Details=%s:%s, %s',
                    server, port, 'CLOSED')
        return False
    finally:
        conn.unbind()

    if conn.bind() is True:
        logger.info('LDAP anonymous bind success, Details=%s:%s, %s',
                    server, port, show_open())
        result = True
    else:
        logger.info('LDAP anonymous bind failed, Details=%s:%s, %s',
                    server, port, 'CLOSED')
        result = False

    return result
