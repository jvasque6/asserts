# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.cloud packages."""

# standard imports
import os

# 3rd party imports
# None

# local imports
from fluidasserts.cloud import aws_cloudtrail


# Constants
AWS_ACCESS_KEY_ID="AKIAIHT6LQIROIL7LKYQ"
AWS_SECRET_ACCESS_KEY="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"
AWS_SECRET_ACCESS_KEY_BAD="bad"

#
# Open tests
#

#
# Closing tests
#

def test_trails_not_multiregion_close():
    """Search if trails are multiregion."""
    assert not aws_cloudtrail.trails_not_multiregion(AWS_ACCESS_KEY_ID,
                                                     AWS_SECRET_ACCESS_KEY)
    assert not aws_cloudtrail.trails_not_multiregion(AWS_ACCESS_KEY_ID,
                                                     AWS_SECRET_ACCESS_KEY_BAD)

    os.environ['http_proxy'] = 'https://0.0.0.0:8080'
    os.environ['https_proxy'] = 'https://0.0.0.0:8080'

    assert not aws_cloudtrail.trails_not_multiregion(AWS_ACCESS_KEY_ID,
                                                     AWS_SECRET_ACCESS_KEY)
    os.environ.pop('http_proxy', None)
    os.environ.pop('https_proxy', None)
