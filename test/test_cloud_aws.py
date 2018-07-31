# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.cloud packages."""

# standard imports
import os

# 3rd party imports
# None

# local imports
from fluidasserts.cloud import aws


# Constants
AWS_ACCESS_KEY_ID="AKIAJ2C5RAAC554PAUOQ"
AWS_SECRET_ACCESS_KEY="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"
AWS_SECRET_ACCESS_KEY_BAD="bad"

#
# Open tests
#


#def test_has_mfa_disabled_open():
#    """Search MFA on IAM users."""
#    assert aws.iam_has_mfa_disabled(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)


#
# Closing tests
#

def test_has_mfa_disabled_close():
    """Search MFA on IAM users."""
    assert not aws.iam_has_mfa_disabled(AWS_ACCESS_KEY_ID,
                                        AWS_SECRET_ACCESS_KEY)
    assert not aws.iam_has_mfa_disabled(AWS_ACCESS_KEY_ID,
                                        AWS_SECRET_ACCESS_KEY_BAD)

    os.environ['http_proxy'] = 'https://0.0.0.0:8080'
    os.environ['https_proxy'] = 'https://0.0.0.0:8080'

    assert not aws.iam_has_mfa_disabled(AWS_ACCESS_KEY_ID,
                                        AWS_SECRET_ACCESS_KEY)
    os.environ.pop('http_proxy', None)
    os.environ.pop('https_proxy', None)


def test_have_old_creds_enabled_close():
    """Search old unused passwords."""
    assert not aws.iam_have_old_creds_enabled(AWS_ACCESS_KEY_ID,
                                              AWS_SECRET_ACCESS_KEY)
    assert not aws.iam_have_old_creds_enabled(AWS_ACCESS_KEY_ID,
                                              AWS_SECRET_ACCESS_KEY_BAD)

    os.environ['http_proxy'] = 'https://0.0.0.0:8080'
    os.environ['https_proxy'] = 'https://0.0.0.0:8080'

    assert not aws.iam_have_old_creds_enabled(AWS_ACCESS_KEY_ID,
                                              AWS_SECRET_ACCESS_KEY)
    os.environ.pop('http_proxy', None)
    os.environ.pop('https_proxy', None)


def test_have_old_access_keys_close():
    """Search old access keys."""
    assert not aws.iam_have_old_access_keys(AWS_ACCESS_KEY_ID,
                                            AWS_SECRET_ACCESS_KEY)
    assert not aws.iam_have_old_access_keys(AWS_ACCESS_KEY_ID,
                                            AWS_SECRET_ACCESS_KEY_BAD)

    os.environ['http_proxy'] = 'https://0.0.0.0:8080'
    os.environ['https_proxy'] = 'https://0.0.0.0:8080'

    assert not aws.iam_have_old_access_keys(AWS_ACCESS_KEY_ID,
                                            AWS_SECRET_ACCESS_KEY)
    os.environ.pop('http_proxy', None)
    os.environ.pop('https_proxy', None)


def test_not_requires_uppercase_close():
    """Search IAM policy: Uppercase letter requirement."""
    assert not aws.iam_not_requires_uppercase(AWS_ACCESS_KEY_ID,
                                              AWS_SECRET_ACCESS_KEY)
    assert not aws.iam_not_requires_uppercase(AWS_ACCESS_KEY_ID,
                                              AWS_SECRET_ACCESS_KEY_BAD)

    os.environ['http_proxy'] = 'https://0.0.0.0:8080'
    os.environ['https_proxy'] = 'https://0.0.0.0:8080'

    assert not aws.iam_not_requires_uppercase(AWS_ACCESS_KEY_ID,
                                              AWS_SECRET_ACCESS_KEY)
    os.environ.pop('http_proxy', None)
    os.environ.pop('https_proxy', None)


def test_not_requires_lowercase_close():
    """Search IAM policy: Lowercase letter requirement."""
    assert not aws.iam_not_requires_lowercase(AWS_ACCESS_KEY_ID,
                                              AWS_SECRET_ACCESS_KEY)
    assert not aws.iam_not_requires_lowercase(AWS_ACCESS_KEY_ID,
                                              AWS_SECRET_ACCESS_KEY_BAD)

    os.environ['http_proxy'] = 'https://0.0.0.0:8080'
    os.environ['https_proxy'] = 'https://0.0.0.0:8080'

    assert not aws.iam_not_requires_lowercase(AWS_ACCESS_KEY_ID,
                                              AWS_SECRET_ACCESS_KEY)
    os.environ.pop('http_proxy', None)
    os.environ.pop('https_proxy', None)
