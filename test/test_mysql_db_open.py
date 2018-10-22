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


#
# Open tests
#


@pytest.mark.parametrize('run_mock',
                         [('mysql_db:weak', {'3306/tcp': OS_PORT})],
                         indirect=True)
def test_test_db_present_open(run_mock):
    """MySQL 'test' DB present?."""
    assert mysql_db.test_db_exists(run_mock, ADMIN_USER, ADMIN_PASS)


def test_local_infile_open(run_mock):
    """MySQL 'local_infile' on?."""
    assert mysql_db.local_infile_enabled(run_mock, ADMIN_USER, ADMIN_PASS)


def test_symlinks_enabled_open(run_mock):
    """MySQL symlinks enabled?."""
    assert mysql_db.symlinks_enabled(run_mock, ADMIN_USER, ADMIN_PASS)


def test_secure_file_open(run_mock):
    """MySQL secure_file_priv enabled?."""
    assert mysql_db.secure_file_priv_disabled(run_mock, ADMIN_USER,
                                              ADMIN_PASS)


def test_strict_all_tables_open(run_mock):
    """STRICT_ALL_TABLES enabled?."""
    assert mysql_db.strict_all_tables_disabled(run_mock, ADMIN_USER,
                                               ADMIN_PASS)


def test_log_error_open(run_mock):
    """MySQL log_error enabled?."""
    assert mysql_db.log_error_disabled(run_mock, ADMIN_USER,
                                       ADMIN_PASS)


def test_logs_on_systemfs_open(run_mock):
    """MySQL logs on system filesystems enabled?."""
    assert mysql_db.logs_on_system_fs(run_mock, ADMIN_USER,
                                      ADMIN_PASS)
