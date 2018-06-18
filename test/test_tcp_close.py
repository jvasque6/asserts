# -*- coding: utf-8 -*-

"""Modulo para pruebas de TCP.

Este modulo contiene las funciones necesarias para probar si el modulo de
tcp se encuentra adecuadamente implementado.
"""

# standard imports
from __future__ import print_function

# 3rd party imports
import pytest

# local imports
from fluidasserts.proto import tcp


# Constants

HARD_PORT = 443
WEAK_PORT = 21
NON_EXISTANT = '0.0.0.0'

#
# Open tests
#


@pytest.mark.parametrize('run_mock',
                         [('tcp:hard', {'21/tcp': HARD_PORT})],
                         indirect=True)
def test_port_open_close(run_mock):
    """Check open port."""
    assert not tcp.is_port_open(run_mock, WEAK_PORT)
    assert not tcp.is_port_open(NON_EXISTANT, WEAK_PORT)


def test_port_insecure_close(run_mock):
    """Check secure port."""
    assert not tcp.is_port_insecure(run_mock, HARD_PORT)
    assert not tcp.is_port_insecure(NON_EXISTANT, HARD_PORT)
