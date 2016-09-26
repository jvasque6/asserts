# -*- coding: utf-8 -*-
"""
Modulo LDAP
"""

# standard imports
import logging
import socket

# 3rd party imports
import ssl
from ldap3 import Server, Connection, Tls

# local imports
# None

PORT = 389
SSL_PORT = 636

def is_anonymous_bind_allowed(server):
    """
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
        conn.close()
    
    if conn.bind() == True:
        logging.info('LDAP anonymous bind success, Details=%s, %s',
                     server, 'OPEN')
        result = True
    else:
        logging.info('LDAP anonymous bind failed, Details=%s, %s',
                     server, 'CLOSED')
        result = False

    return result
