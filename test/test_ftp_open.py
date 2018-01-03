# -*- coding: utf-8 -*-

"""Modulo para pruebas de FTP.

Este modulo contiene las funciones necesarias para probar si el modulo de
FTP se encuentra adecuadamente implementado.

El mock se encuentra implementado como un contenedor Docker con alpine
linux y dos configuraciones, una vulnerable y una endurecida del servidor
VSFTP

"""

# standard imports
from __future__ import print_function
import subprocess

# 3rd party imports
import pytest

# local imports
from fluidasserts.service import ftp


#
# Constants
#

CONTAINER_IP = '172.30.216.101'
ADMIN_PASS = 'ahViQu9E'
NONPASS_USER = 'nonpass'
SECURED_USER = 'secured'
GUESSED_USER = 'guessed'
GUESSED_PASS = 'guessed123'
FTP_PORT = 21

#
# Open tests
#


@pytest.mark.parametrize('run_mock',
                         [('ftp:weak', {'21/tcp': FTP_PORT})],
                         indirect=True)
def test_is_anonymous_enabled_open(run_mock):
    """Servidor FTP vulnerable SI soporta conexion anonima?"""
    assert ftp.is_anonymous_enabled(CONTAINER_IP)


@pytest.mark.parametrize('run_mock',
                         [('ftp:weak', {'21/tcp': FTP_PORT})],
                         indirect=True)
def test_is_admin_enabled_open(run_mock):
    """Servidor FTP vulnerable SI soporta conexion del ADMIN"""
    assert ftp.is_admin_enabled(CONTAINER_IP, ADMIN_PASS)


@pytest.mark.parametrize('run_mock',
                         [('ftp:weak', {'21/tcp': FTP_PORT})],
                         indirect=True)
def test_user_without_password_open(run_mock):
    """Servidor FTP vulnerable SI autentica usuario sin clave?"""
    assert ftp.user_without_password(CONTAINER_IP, NONPASS_USER)


@pytest.mark.parametrize('run_mock',
                         [('ftp:weak', {'21/tcp': FTP_PORT})],
                         indirect=True)
def test_is_a_valid_user_open(run_mock):
    """Servidor FTP vulnerable SI autentica a usuario adivinado?"""
    assert ftp.is_a_valid_user(CONTAINER_IP, GUESSED_USER, GUESSED_PASS)


@pytest.mark.parametrize('run_mock',
                         [('ftp:weak', {'21/tcp': FTP_PORT})],
                         indirect=True)
def test_is_version_visible_open(run_mock):
    """Servidor FTP vulnerable SI muestra version?"""
    assert ftp.is_version_visible(CONTAINER_IP)
