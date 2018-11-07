# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.cloud packages."""

# standard imports
import os

# 3rd party imports
# None

# local imports
from fluidasserts.cloud import aws_ec2


# Constants
AWS_ACCESS_KEY_ID="AKIAIHT6LQIROIL7LKYQ"
AWS_SECRET_ACCESS_KEY="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"
AWS_SECRET_ACCESS_KEY_BAD="bad"

#
# Open tests
#


def test_defgroup_anyone_open():
    """Security groups allows connection to or from anyone?."""
    assert \
        aws_ec2.default_seggroup_allows_all_traffic(AWS_ACCESS_KEY_ID,
                                                    AWS_SECRET_ACCESS_KEY)


def test_unencrypted_volumes_open():
    """Are there unencrypted volumes?."""
    assert \
        aws_ec2.has_unencrypted_volumes(AWS_ACCESS_KEY_ID,
                                        AWS_SECRET_ACCESS_KEY)



#
# Closing tests
#

def test_anyone_to_ssh_close():
    """Seg group allows anyone to connect to SSH?."""
    assert not aws_ec2.seggroup_allows_anyone_to_ssh(AWS_ACCESS_KEY_ID,
                                                     AWS_SECRET_ACCESS_KEY)
    assert not aws_ec2.seggroup_allows_anyone_to_ssh(AWS_ACCESS_KEY_ID,
                                                     AWS_SECRET_ACCESS_KEY_BAD)

    os.environ['http_proxy'] = 'https://0.0.0.0:8080'
    os.environ['https_proxy'] = 'https://0.0.0.0:8080'

    assert not aws_ec2.seggroup_allows_anyone_to_ssh(AWS_ACCESS_KEY_ID,
                                                     AWS_SECRET_ACCESS_KEY)
    os.environ.pop('http_proxy', None)
    os.environ.pop('https_proxy', None)


def test_anyone_to_rdp_close():
    """Seg group allows anyone to connect to RDP?."""
    assert not aws_ec2.seggroup_allows_anyone_to_rdp(AWS_ACCESS_KEY_ID,
                                                     AWS_SECRET_ACCESS_KEY)
    assert not aws_ec2.seggroup_allows_anyone_to_rdp(AWS_ACCESS_KEY_ID,
                                                     AWS_SECRET_ACCESS_KEY_BAD)

    os.environ['http_proxy'] = 'https://0.0.0.0:8080'
    os.environ['https_proxy'] = 'https://0.0.0.0:8080'

    assert not aws_ec2.seggroup_allows_anyone_to_rdp(AWS_ACCESS_KEY_ID,
                                                     AWS_SECRET_ACCESS_KEY)
    os.environ.pop('http_proxy', None)
    os.environ.pop('https_proxy', None)


def test_defgroup_anyone_close():
    """Security groups allows connection to or from anyone?."""
    assert not \
        aws_ec2.default_seggroup_allows_all_traffic(AWS_ACCESS_KEY_ID,
                                                     AWS_SECRET_ACCESS_KEY_BAD)

    os.environ['http_proxy'] = 'https://0.0.0.0:8080'
    os.environ['https_proxy'] = 'https://0.0.0.0:8080'

    assert not \
        aws_ec2.default_seggroup_allows_all_traffic(AWS_ACCESS_KEY_ID,
                                                    AWS_SECRET_ACCESS_KEY)
    os.environ.pop('http_proxy', None)
    os.environ.pop('https_proxy', None)


def test_unencrypted_volumes_close():
    """Are there unencrypted volumes?."""
    assert not \
        aws_ec2.has_unencrypted_volumes(AWS_ACCESS_KEY_ID,
                                        AWS_SECRET_ACCESS_KEY_BAD)

    os.environ['http_proxy'] = 'https://0.0.0.0:8080'
    os.environ['https_proxy'] = 'https://0.0.0.0:8080'

    assert not \
        aws_ec2.has_unencrypted_volumes(AWS_ACCESS_KEY_ID,
                                        AWS_SECRET_ACCESS_KEY)
    os.environ.pop('http_proxy', None)
    os.environ.pop('https_proxy', None)
