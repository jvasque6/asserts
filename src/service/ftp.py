# -*- coding: utf-8 -*-

"""Modulo para verificación del protocolo FTP.

Este modulo permite verificar vulnerabilidades propias de FTP como:

    * is_a_valid_user: Usuario puede autenticarse,
    * is_admin_enabled: Administrador puede autenticarse,
    * is_anonymous_enabled: Conexión al servicio de forma anonima,
    * user_without_password: Usuario sin clave puede autenticarse,

Futuras funciones incluyen:

    * is_encrypted: Transporte de información de forma plana,
    * has_advisory: Tiene advisory de conexion ante login,
"""

# standard imports
import logging
from ftplib import FTP, error_perm

# 3rd party imports
# none

# local imports
# none

PORT = 21
NULL_PASSWORD = ''
ADMIN_USERNAME = 'root'
ANONYMOUS_USERNAME = 'anonymous'
ANONYMOUS_PASSWORD = 'anonymous'


def is_a_valid_user(ip_address, username, password, port=PORT):
    """Determina via FTP si un usuario es valido o no."""
    result = False
    try:
        ftp = FTP()
        ftp.connect(ip_address, port)
        ftp.login(username, password)
        ftp.quit()
        result = True
        logging.info('FTP Authentication %s, Details=%s, %s',
                     ip_address, username + ':' + password, 'OPEN')
    except error_perm:
        logging.info('FTP Authentication %s, Details=%s, %s',
                     ip_address, username + ':' + password, 'CLOSE')
        result = False
    return result


def user_without_password(ip_address, username):
    """Determina si el usuario no tiene clave."""
    return is_a_valid_user(ip_address, username, password=NULL_PASSWORD)


def is_anonymous_enabled(ip_address):
    """Determina si un servidor FTP tiene habilitado conexión anonima."""
    return is_a_valid_user(ip_address, ANONYMOUS_USERNAME, ANONYMOUS_PASSWORD)


def is_admin_enabled(ip_address, password, username=ADMIN_USERNAME):
    """Determina si un servidor FTP permite autenticar al administrador."""
    return is_a_valid_user(ip_address, username, password)
