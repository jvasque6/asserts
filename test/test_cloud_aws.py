# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.cloud packages."""

# standard imports
import os

# 3rd party imports
# None

# local imports
from fluidasserts.cloud import aws


# Constants
AWS_ACCESS_KEY_ID="AKIAJJHZGEKNKPPM4VOA"
AWS_SECRET_ACCESS_KEY="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"
AWS_SECRET_ACCESS_KEY_BAD="bad"

#
# Open tests
#


#def test_has_mfa_disabled_open():
#    """Search MFA on IAM users."""
#    assert aws.has_mfa_disabled(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)


#
# Closing tests
#

def test_has_mfa_disabled_close():
    """Search MFA on IAM users."""
    assert not aws.has_mfa_disabled(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    assert not aws.has_mfa_disabled(AWS_ACCESS_KEY_ID,
                                    AWS_SECRET_ACCESS_KEY_BAD)

    os.environ['http_proxy'] = 'https://0.0.0.0:8080'
    os.environ['https_proxy'] = 'https://0.0.0.0:8080'

    assert not aws.has_mfa_disabled(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    os.environ.pop('http_proxy', None)
    os.environ.pop('https_proxy', None)
