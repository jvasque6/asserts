# -*- coding: utf-8 -*-

"""This module allows to check LDAP vulnerabilities."""

# standard imports
# None

# 3rd party imports
from ldap3 import Connection
from ldap3.core.exceptions import LDAPExceptionError, LDAPSocketOpenError
from ldap3 import Server

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track, level

PORT = 389
SSL_PORT = 636


@level('high')
@track
def is_anonymous_bind_allowed(ldap_server: str, port: int = PORT) -> bool:
    """
    Check whether anonymous binding is allowed on LDAP server.

    :param ldap_server: LDAP server address to test.
    :param port: If necessary, specify port to connect to.
    """
    result = True

    try:
        server = Server(ldap_server)
        conn = Connection(server)

    except LDAPExceptionError:
        show_close('LDAP anonymous bind failed',
                   details=dict(server=ldap_server, port=port))
        return False
    finally:
        conn.unbind()

    try:
        if conn.bind() is True:
            print(server)
            print(port)
            show_open('LDAP anonymous bind success',
                      details=dict(server=ldap_server, port=port))
            result = True
        else:
            show_close('LDAP anonymous bind failed',
                       details=dict(server=ldap_server, port=port))
            result = False
    except LDAPSocketOpenError as exc:
        show_unknown('Could not connect',
                     details=dict(server=ldap_server,
                                  port=port,
                                  error=str(exc).replace(':', ',')))
        return False
    return result
