# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.proto.git."""

# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts.proto import git


# Constants

COMMIT_ID = 'aaf0312e43ed7637c69af34bba59897f0e0810f8'
BAD_COMMIT_ID = '123123'
REPO_PATH = '.'


#
# Open tests
#


def test_commit_has_secret_open():
    """Commit has secret?."""
    assert git.commit_has_secret(REPO_PATH, COMMIT_ID, 'CaselessKeyword')


#
# Closing tests
#


def test_commit_has_secret_close():
    """Commit has secret?."""
    assert not git.commit_has_secret(REPO_PATH, BAD_COMMIT_ID,
                                     'CaselessKeyword')
    assert not git.commit_has_secret(REPO_PATH, COMMIT_ID, 'NotFoundString')
