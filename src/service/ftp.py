# -*- coding: utf-8 -*-

"""Modulo para verificacion del protocolo FTP.

Este modulo permite verificar vulnerabilidades propias de FTP como:

    * is_a_valid_user: Usuario puede autenticarse,
    * is_admin_enabled: Administrador puede autenticarse,
    * is_anonymous_enabled: Conexion al servicio de forma anonima,
    * user_without_password: Usuario sin clave puede autenticarse,

Futuras funciones incluyen:

    * is_encrypted: Transporte de informacion de forma plana,
    * has_advisory: Tiene advisory de conexion ante login,
"""

# standard imports
from ftplib import error_perm
from ftplib import FTP
import logging


# 3rd party imports
# none

# local imports
from fluidasserts.helper import banner_helper

PORT = 21
NULL_PASSWORD = ''
ADMIN_USERNAME = 'root'
ANONYMOUS_USERNAME = 'anonymous'
ANONYMOUS_PASSWORD = 'anonymous'

logger = logging.getLogger('FLUIDAsserts')


def is_a_valid_user(ip_address, username, password, port=PORT):
    """Determina via FTP si un usuario es valido o no."""
    result = False
    try:
        ftp = FTP()
        ftp.connect(ip_address, port)
        ftp.login(username, password)
        ftp.quit()
        result = True
        logger.info('FTP Authentication %s, Details=%s, %s',
                    ip_address, username + ':' + password, 'OPEN')
    except error_perm:
        logger.info('FTP Authentication %s, Details=%s, %s',
                    ip_address, username + ':' + password, 'CLOSE')
        result = False
    return result


def user_without_password(ip_address, username):
    """Determina si el usuario no tiene clave."""
    return is_a_valid_user(ip_address, username, password=NULL_PASSWORD)


def is_anonymous_enabled(ip_address):
    """Determina si un servidor FTP tiene habilitado conexion anonima."""
    return is_a_valid_user(ip_address, ANONYMOUS_USERNAME, ANONYMOUS_PASSWORD)


def is_admin_enabled(ip_address, password, username=ADMIN_USERNAME):
    """Determina si un servidor FTP permite autenticar al administrador."""
    return is_a_valid_user(ip_address, username, password)


def is_version_visible(ip_address):
    """Check if banner is visible."""
    service = banner_helper.FTPService()
    banner = banner_helper.get_banner(service, ip_address)
    version = banner_helper.get_version(service, banner)

    result = True
    if version:
        result = True
        logger.info('FTP version visible on %s, Details=%s, %s, %s',
                    ip_address, banner, version, 'OPEN')
    else:
        result = False
        logger.info('FTP version not visible on %s, Details=None, %s',
                    ip_address, 'CLOSE')
    return result
