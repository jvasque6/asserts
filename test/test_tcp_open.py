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

WEAK_PORT = 80

#
# Open tests
#


@pytest.mark.parametrize('run_mock',
                         [('tcp:weak', {'21/tcp': WEAK_PORT})],
                         indirect=True)
def test_port_open_open(run_mock):
    """Check open port."""
    assert tcp.is_port_open(run_mock, WEAK_PORT)


def test_port_open_error(run_mock):
    """Check open port with error."""
    with pytest.raises(AssertionError):
        tcp.is_port_open(run_mock, -1)


def test_port_insecure_open(run_mock):
    """Check secure port."""
    assert tcp.is_port_insecure(run_mock, WEAK_PORT)
