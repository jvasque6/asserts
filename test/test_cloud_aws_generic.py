# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.cloud packages."""

# standard imports
import os

# 3rd party imports
# None

# local imports
from fluidasserts.cloud.aws import generic


# Constants
AWS_ACCESS_KEY_ID = os.environ['AWS_ACCESS_KEY_ID']
AWS_SECRET_ACCESS_KEY = os.environ['AWS_SECRET_ACCESS_KEY']
AWS_SECRET_ACCESS_KEY_BAD = "bad"

#
# Open tests
#


def test_credencials_valid_open():
    """Check credentials valid."""
    assert generic.are_valid_credentials(AWS_ACCESS_KEY_ID,
                                         AWS_SECRET_ACCESS_KEY)

#
# Closing tests
#


def test_credencials_valid_close():
    """Check credentials valid."""
    assert not generic.are_valid_credentials(AWS_ACCESS_KEY_ID,
                                             AWS_SECRET_ACCESS_KEY_BAD)

    os.environ['http_proxy'] = 'https://0.0.0.0:8080'
    os.environ['https_proxy'] = 'https://0.0.0.0:8080'

    assert not generic.are_valid_credentials(AWS_ACCESS_KEY_ID,
                                             AWS_SECRET_ACCESS_KEY)
    os.environ.pop('http_proxy', None)
    os.environ.pop('https_proxy', None)
