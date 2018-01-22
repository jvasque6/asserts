# -*- coding: utf-8 -*-

"""Modulo para pruebas de SMTP.

Este modulo contiene las funciones necesarias para probar si el modulo de
SMTP se encuentra adecuadamente implementado.
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
# Open tests
#


@pytest.mark.parametrize('run_mock',
                         [('smtp:weak', {'25/tcp': WEAK_PORT})],
                         indirect=True)
# pylint: disable=unused-argument
def test_has_vrfy_open(run_mock):
    """Funcion VRFY habilitada?."""
    assert smtp.has_vrfy(CONTAINER_IP, WEAK_PORT)


def test_is_version_visible_open(run_mock):
    """Check version visible."""
    assert smtp.is_version_visible(CONTAINER_IP, WEAK_PORT)
