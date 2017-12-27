# -*- coding: utf-8 -*-

"""Modulo para pruebas de SSL.

Este modulo contiene las funciones necesarias para probar si el modulo de
SSL se encuentra adecuadamente implementado.
"""

# standard imports
from __future__ import print_function

# 3rd party imports
import pytest

# local imports
from fluidasserts.service import smtp

# Constants
CONTAINER_IP = '172.30.216.101'
WEAK_PORT = 25
HARD_PORT = 25

#
# Closing tests
#


@pytest.mark.parametrize('run_mock',
                         [('smtp:hard', {'25/tcp': HARD_PORT})],
                         indirect=True)
def test_has_vrfy_close(run_mock):
    """Funcion VRFY habilitada?"""
    assert not smtp.has_vrfy(CONTAINER_IP, HARD_PORT)


# Pendente implementar resto de metodos
