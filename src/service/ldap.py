# -*- coding: utf-8 -*-
"""
Modulo LDAP
"""

# standard imports
import logging

# 3rd party imports
from ldap3 import Connection
from ldap3 import Server

# local imports
# None

PORT = 389
SSL_PORT = 636


def is_anonymous_bind_allowed(server):
    """function is_anonymous_bind_allowed

    Function to check whether anonymous binding is allowed on
    LDAP server
    """
    result = True

    try:
        server = Server(server)
        conn = Connection(server)
    except:
        logging.info('LDAP anonymous bind failed, Details=%s, %s',
                     server, 'CLOSED')
        return False
    finally:
        conn.unbind()

    if conn.bind() is True:
        logging.info('LDAP anonymous bind success, Details=%s, %s',
                     server, 'OPEN')
        result = True
    else:
        logging.info('LDAP anonymous bind failed, Details=%s, %s',
                     server, 'CLOSED')
        result = False

    return result
