# -*- coding: utf-8 -*-

"""Modulo para pruebas de LDAP.

Este modulo contiene las funciones necesarias para probar si el modulo de
LDAP se encuentra adecuadamente implementado.
"""

# standard imports
from __future__ import print_function

# 3rd party imports
import pytest

# local imports
from fluidasserts.proto import ldap
import fluidasserts.utils.decorators

# Constants
fluidasserts.utils.decorators.UNITTEST = True
WEAK_PORT = 389

#
# Open tests
#


@pytest.mark.parametrize('run_mock',
                         [('ldap:weak', {'389/tcp': WEAK_PORT})],
                         indirect=True)
def test_is_anonymous_bind_allowed_open(run_mock):
    """Test if anonymous bind allowed?."""
    assert ldap.is_anonymous_bind_allowed(run_mock, WEAK_PORT)
