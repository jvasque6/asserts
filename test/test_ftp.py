# -*- coding: utf-8 -*-

"""Modulo para pruebas de FTP.

Este modulo contiene las funciones necesarias para probar si el modulo de
FTP se encuentra adecuadamente implementado.

El mock se encuentra implementado como un contenedor Docker con alpine
linux y dos configuraciones, una vulnerable y una endurecida del servidor
VSFTP

"""

# standard imports
# none

# 3rd party imports
# none

# local imports
from fluidasserts import ftp

IP_HARDENED = '10.82.21.77'
IP_VULNERABLE = '10.82.21.66'

ADMIN_PASSWORD = 'root123'
NONPASS_USERNAME = 'dario'
SECURED_USERNAME = 'freddy'
GUESSED_USERNAME = 'faustino'
GUESSED_PASSWORD = 'faustino123'
CHANGED_SUFFIX = 'CHANGED'


def test_is_anonymous_enabled_open():
    """Servidor FTP vulnerable SI soporta conexion anonima?"""
    assert ftp.is_anonymous_enabled(IP_VULNERABLE)


def test_is_anonymous_enabled_close():
    """Servidor FTP endurecido NO soporta conexion anonima?"""
    assert not ftp.is_anonymous_enabled(IP_HARDENED)


def test_is_admin_enabled_open():
    """Servidor FTP vulnerable SI soporta conexion del ADMIN"""
    assert ftp.is_admin_enabled(IP_VULNERABLE,
                                ADMIN_PASSWORD)


def test_is_admin_enabled_close():
    """Servidor FTP endurecido NO soporta conexion del ADMIN?"""
    # TODO(ralvarez) Idealmente mismas credenciales en HARDENED
    assert not ftp.is_admin_enabled(IP_HARDENED,
                                    (ADMIN_PASSWORD + CHANGED_SUFFIX))


def test_user_without_password_open():
    """Servidor FTP vulnerable SI autentica usuario sin clave?"""
    assert ftp.user_without_password(IP_VULNERABLE,
                                     NONPASS_USERNAME)


def test_user_without_password_close():
    """Servidor FTP endurecido NO autentica usuario sin clave"""
    # TODO(ralvarez) Idealmente mismas credenciales en HARDENED
    assert not ftp.user_without_password(IP_HARDENED,
                                         SECURED_USERNAME)


def test_is_a_valid_user_open():
    """Servidor FTP vulnerable SI autentica a usuario adivinado?"""
    assert ftp.is_a_valid_user(IP_VULNERABLE,
                               GUESSED_USERNAME,
                               GUESSED_PASSWORD)


def test_is_a_valid_user_close():
    """Servidor FTP endurecido NO autentica a usuario adivinado?"""
    # TODO(ralvarez) Idealmente mismas credenciales en HARDENED
    assert not ftp.is_a_valid_user(IP_HARDENED,
                                   GUESSED_USERNAME,
                                   (GUESSED_PASSWORD + CHANGED_SUFFIX))
