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
HARD_PORT = 389
NON_EXISTANT = '0.0.0.0'

#
# Open tests
#


@pytest.mark.parametrize('run_mock',
                         [('ldap:hard', {'389/tcp': HARD_PORT})],
                         indirect=True)
def test_is_anonymous_bind_allowed_close(run_mock):
    """Test if anonymous bind allowed?."""
    assert not ldap.is_anonymous_bind_allowed(NON_EXISTANT, HARD_PORT)
