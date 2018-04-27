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
from fluidasserts.service import smb
import fluidasserts.utils.decorators

# Constants
fluidasserts.utils.decorators.UNITTEST = True
CONTAINER_IP = '172.30.216.101'
SMB_PORT = 445


@pytest.mark.parametrize('run_mock',
                         [('smb:hard', {'445/tcp': SMB_PORT})],
                         indirect=True)
# pylint: disable=unused-argument
def test_is_anonymous_enabled_close(run_mock):
    """Conexion anonima habilitada?."""
    assert not smb.is_anonymous_enabled(CONTAINER_IP)
    assert not smb.is_anonymous_enabled(CONTAINER_IP+':446')


# pylint: disable=unused-argument
def test_has_dirlisting_close(run_mock):
    """Conexion anonima habilitada?."""
    assert not smb.has_dirlisting('/public',
                                  server=CONTAINER_IP,
                                  user="root",
                                  password='Puef8poh2tei9AeB',
                                  domain='WORKGROUP')
