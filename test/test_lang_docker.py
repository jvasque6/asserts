# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.code.docker."""

# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts.lang import docker


# Constants

CODE_DIR = 'test/static/lang/docker/'
SECURE_CODE = CODE_DIR + 'Dockerfile.close'
INSECURE_CODE = CODE_DIR + 'Dockerfile.open'
NOT_EXISTANT_CODE = CODE_DIR + 'NotExistant.open'


#
# Open tests
#


def test_not_pinned_open():
    """Search for pinned dockerfile."""
    assert docker.not_pinned(INSECURE_CODE)

#
# Closing tests
#


def test_not_pinned_close():
    """Search for pinned dockerfile."""
    assert not docker.not_pinned(SECURE_CODE)
    assert not docker.not_pinned(NOT_EXISTANT_CODE)
