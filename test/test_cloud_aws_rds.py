# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.cloud packages."""

# standard imports
import os

# 3rd party imports
# None

# local imports
from fluidasserts.cloud.aws import rds


# Constants
AWS_ACCESS_KEY_ID = os.environ['AWS_ACCESS_KEY_ID']
AWS_SECRET_ACCESS_KEY = os.environ['AWS_SECRET_ACCESS_KEY']
AWS_SECRET_ACCESS_KEY_BAD = "bad"

#
# Open tests
#


#
# Closing tests
#


def test_instance_public_close():
    """RDS instance public?."""
    assert not rds.has_public_instances(AWS_ACCESS_KEY_ID,
                                        AWS_SECRET_ACCESS_KEY_BAD)

    os.environ['http_proxy'] = 'https://0.0.0.0:8080'
    os.environ['https_proxy'] = 'https://0.0.0.0:8080'

    assert not rds.has_public_instances(AWS_ACCESS_KEY_ID,
                                        AWS_SECRET_ACCESS_KEY)
    os.environ.pop('http_proxy', None)
    os.environ.pop('https_proxy', None)
