# -*- coding: utf-8 -*-

"""SOAP module.

This module allows to check LDAP especific vulnerabilities
"""
# standard imports
import logging

# third party imports
# None

# local imports
from fluidasserts.utils.decorators import track

LOGGER = logging.getLogger('FLUIDAsserts')


@track
def soap_is_enable():
    """Check if SOAP WS is enabled."""
    pass
