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

#
# Open tests
#


@pytest.mark.parametrize('run_mock',
                         [('smb:weak', {'445/tcp': SMB_PORT})],
                         indirect=True)
def test_is_anonymous_enabled_open(run_mock):
    """Conexion anonima habilitada?."""
    assert smb.is_anonymous_enabled(run_mock)


def test_has_dirlisting_open(run_mock):
    """Conexion anonima habilitada?."""
    assert smb.has_dirlisting('public',
                              server=run_mock,
                              user="root",
                              password='Puef8poh2tei9AeB',
                              domain='WORKGROUP')


def test_is_signing_disabled_open(run_mock):
    """SMB connection signed?."""
    assert smb.is_signing_disabled(server=run_mock,
                                   user="root",
                                   password='Puef8poh2tei9AeB',
                                   domain='WORKGROUP')
