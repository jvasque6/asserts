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



def test_local_infile_close(run_mock):
    """MySQL 'local_infile' on?."""
    #assert not mysql_db.local_infile_enabled(run_mock, ADMIN_USER,
    #                                         ADMIN_PASS)
    assert not mysql_db.local_infile_enabled(NON_EXISTANT, ADMIN_USER,
                                             ADMIN_PASS)


def test_symlinks_enabled_close(run_mock):
    """MySQL symlinks enabled?."""
    #assert not mysql_db.symlinks_enabled(run_mock, ADMIN_USER,
    #                                         ADMIN_PASS)
    assert not mysql_db.symlinks_enabled(NON_EXISTANT, ADMIN_USER,
                                             ADMIN_PASS)


def test_memcached_enabled_close(run_mock):
    """MySQL memcached enabled?."""
    assert not mysql_db.memcached_enabled(run_mock, ADMIN_USER,
                                          ADMIN_PASS)
    assert not mysql_db.memcached_enabled(NON_EXISTANT, ADMIN_USER,
                                          ADMIN_PASS)


def test_secure_file_close(run_mock):
    """MySQL secure_file_priv enabled?."""
    #assert not mysql_db.secure_file_priv_disabled(run_mock, ADMIN_USER,
    #                                      ADMIN_PASS)
    assert not mysql_db.secure_file_priv_disabled(NON_EXISTANT, ADMIN_USER,
                                                  ADMIN_PASS)
