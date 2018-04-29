# -*- coding: utf-8 -*-
"""LDAP module."""

# standard imports
# None

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

@track
def is_anonymous_bind_allowed(ldap_server, port=PORT):
    """Check whether anonymous binding is allowed on LDAP server."""
    result = True

    try:
        server = Server(ldap_server)
        conn = Connection(server)
    except LDAPExceptionError:
        show_close('LDAP anonymous bind failed', details=dict(server=server,
                                                              port=port))
        return False
    finally:
        conn.unbind()

    if conn.bind() is True:
        show_open('LDAP anonymous bind success', details=dict(server=server,
                                                              port=port))
        result = True
    else:
        show_close('LDAP anonymous bind failed', details=dict(server=server,
                                                              port=port))
        result = False

    return result
