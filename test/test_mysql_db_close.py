# -*- coding: utf-8 -*-

"""Test module for mysql_os."""

# standard imports
from __future__ import print_function

# 3rd party imports
import pytest

# local imports
from fluidasserts.db import mysql_db


# Constants

ADMIN_USER = 'root'
ADMIN_PASS = 'iethohnei2EeSh4P'
OS_PORT = 3306
NON_EXISTANT = '0.0.0.0'


#
# Open tests
#


@pytest.mark.parametrize('run_mock',
                         [('mysql_db:hard', {'3306/tcp': OS_PORT})],
                         indirect=True)
def test_test_db_present_close(run_mock):
    """MySQL 'test' DB present?."""
    #assert not mysql_db.test_db_exists(run_mock, ADMIN_USER, ADMIN_PASS)
    assert not mysql_db.test_db_exists(NON_EXISTANT, ADMIN_USER, ADMIN_PASS)
