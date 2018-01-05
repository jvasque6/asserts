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
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.helper import banner_helper
from fluidasserts.utils.decorators import track

PORT = 21
NULL_PASSWORD = ''
ADMIN_USERNAME = 'root'
ANONYMOUS_USERNAME = 'anonymous'
ANONYMOUS_PASSWORD = 'anonymous'

LOGGER = logging.getLogger('FLUIDAsserts')


@track
def is_a_valid_user(ip_address, username, password, port=PORT):
    """Determina via FTP si un usuario es valido o no."""
    result = False
    try:
        ftp = FTP()
        ftp.connect(ip_address, port)
        ftp.login(username, password)
        ftp.quit()
        result = True
        LOGGER.info('%s: FTP Authentication %s:%s, Details=%s',
                    show_open(), ip_address, port,
                    username + ':' + password)
    except error_perm:
        LOGGER.info('%s: FTP Authentication %s:%s, Details=%s',
                    show_close(), ip_address, port,
                    username + ':' + password)
        result = False
    return result


@track
def user_without_password(ip_address, username):
    """Determina si el usuario no tiene clave."""
    return is_a_valid_user(ip_address, username, password=NULL_PASSWORD)


@track
def is_anonymous_enabled(ip_address):
    """Determina si un servidor FTP tiene habilitado conexion anonima."""
    return is_a_valid_user(ip_address, ANONYMOUS_USERNAME, ANONYMOUS_PASSWORD)


@track
def is_admin_enabled(ip_address, password, username=ADMIN_USERNAME):
    """Determina si un servidor FTP permite autenticar al administrador."""
    return is_a_valid_user(ip_address, username, password)


@track
def is_version_visible(ip_address, port=PORT):
    """Check if banner is visible."""
    service = banner_helper.FTPService()
    banner = banner_helper.get_banner(service, ip_address)
    version = banner_helper.get_version(service, banner)

    result = True
    if version:
        result = True
        LOGGER.info('%s: FTP version visible on %s:%s, Details=%s, %s',
                    show_open(), ip_address, port, banner, version)
    else:
        result = False
        LOGGER.info('%s: FTP version not visible on %s, Details=None',
                    show_close(), ip_address)
    return result
