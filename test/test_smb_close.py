# -*- coding: utf-8 -*-

"""Modulo para pruebas de SMB.

Este modulo contiene las funciones necesarias para probar si el modulo de
SMB se encuentra adecuadamente implementado.
"""

# standard imports
from __future__ import print_function

# 3rd party imports
import pytest

# local imports
from fluidasserts.proto import smb
import fluidasserts.utils.decorators

# Constants
fluidasserts.utils.decorators.UNITTEST = True
SMB_PORT = 445
NON_EXISTANT = '0.0.0.0'


@pytest.mark.parametrize('run_mock',
                         [('smb:hard', {'445/tcp': SMB_PORT})],
                         indirect=True)
def test_is_anonymous_enabled_close(run_mock):
    """Conexion anonima habilitada?."""
    assert not smb.is_anonymous_enabled(run_mock)

    assert not smb.is_anonymous_enabled(run_mock+':446')


def test_has_dirlisting_close(run_mock):
    """Conexion anonima habilitada?."""
    assert not smb.has_dirlisting('public',
                                  server=run_mock,
                                  user="root",
                                  password='Puef8poh2tei9AeB',
                                  domain='WORKGROUP')
    assert not smb.has_dirlisting('public',
                                  server=NON_EXISTANT,
                                  user="root",
                                  password='Puef8poh2tei9AeB',
                                  domain='WORKGROUP')


def test_is_signing_disabled_close(run_mock):
    """SMB connection signed?."""
    assert not smb.is_signing_disabled(server=run_mock,
                                       user="root",
                                       password='Puef8poh2tei9AeB',
                                       domain='WORKGROUP')
    assert not smb.is_signing_disabled(server=NON_EXISTANT,
                                       user="root",
                                       password='Puef8poh2tei9AeB',
                                       domain='WORKGROUP')
