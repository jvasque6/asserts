# -*- coding: utf-8 -*-

"""Modulo para pruebas de FTP.

Este modulo contiene las funciones necesarias para probar si el modulo de
FTP se encuentra adecuadamente implementado.

El mock se encuentra implementado como un contenedor Docker con alpine
linux y dos configuraciones, una vulnerable y una endurecida del servidor
VSFTP

"""

# standard imports
import subprocess

# 3rd party imports
import pytest

# local imports
from fluidasserts.service import ftp


#
# Constants
#

# TODO(ralvarez): Pueden ser cargadas del hosts ini style
CONTAINER_IP = '172.30.216.100'
ADMIN_PASS = 'ahViQu9E'
NONPASS_USER = 'nonpass'
SECURED_USER = 'secured'
GUESSED_USER = 'guessed'
GUESSED_PASS = 'guessed123'


#
# Fixtures
#

# pylint: disable=unused-argument
@pytest.fixture(scope='module')
def weak_ftp(request):
    """Configura perfil de FTP vulnerable."""
    print('Running FTP vulnerable playbook')
    subprocess.call('ansible-playbook test/provision/ftp.yml \
                                      --tags weak', shell=True)


# pylint: disable=unused-argument
@pytest.fixture(scope='module')
def hard_ftp(request):
    """Configura perfil de FTP endurecido."""
    print('Running FTP hardened playbook')
    subprocess.call('ansible-playbook test/provision/ftp.yml \
                                      --tags hard', shell=True)


#
# Open tests
#


@pytest.mark.usefixtures('container', 'weak_ftp')
def test_is_anonymous_enabled_open():
    """Servidor FTP vulnerable SI soporta conexion anonima?"""
    assert ftp.is_anonymous_enabled(CONTAINER_IP)


@pytest.mark.usefixtures('container', 'weak_ftp')
def test_is_admin_enabled_open():
    """Servidor FTP vulnerable SI soporta conexion del ADMIN"""
    assert ftp.is_admin_enabled(CONTAINER_IP, ADMIN_PASS)


@pytest.mark.usefixtures('container', 'weak_ftp')
def test_user_without_password_open():
    """Servidor FTP vulnerable SI autentica usuario sin clave?"""
    assert ftp.user_without_password(CONTAINER_IP, NONPASS_USER)


@pytest.mark.usefixtures('container', 'weak_ftp')
def test_is_a_valid_user_open():
    """Servidor FTP vulnerable SI autentica a usuario adivinado?"""
    assert ftp.is_a_valid_user(CONTAINER_IP, GUESSED_USER, GUESSED_PASS)


#
# Closing tests
#


@pytest.mark.usefixtures('container', 'hard_ftp')
def test_is_anonymous_enabled_close():
    """Servidor FTP endurecido NO soporta conexion anonima?"""
    assert not ftp.is_anonymous_enabled(CONTAINER_IP)


@pytest.mark.usefixtures('container', 'hard_ftp')
def test_is_admin_enabled_close():
    """Servidor FTP endurecido NO soporta conexion del ADMIN?"""
    assert not ftp.is_admin_enabled(CONTAINER_IP, ADMIN_PASS)


@pytest.mark.usefixtures('container', 'hard_ftp')
def test_user_without_password_close():
    """Servidor FTP endurecido NO autentica usuario sin clave"""
    assert not ftp.user_without_password(CONTAINER_IP, NONPASS_USER)


@pytest.mark.usefixtures('container', 'hard_ftp')
def test_is_a_valid_user_close():
    """Servidor FTP endurecido NO autentica a usuario adivinado?"""
    assert not ftp.is_a_valid_user(CONTAINER_IP, GUESSED_USER, GUESSED_PASS)
