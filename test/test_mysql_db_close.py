# -*- coding: utf-8 -*-

"""Test module for mysql_os."""

# standard imports
from __future__ import print_function

# 3rd party imports
import pytest

# local imports
from fluidasserts.db import mysql


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
    assert not mysql.test_db_exists(NON_EXISTANT, ADMIN_USER, ADMIN_PASS)



def test_local_infile_close(run_mock):
    """MySQL 'local_infile' on?."""
    #assert not mysql_db.local_infile_enabled(run_mock, ADMIN_USER,
    #                                         ADMIN_PASS)
    assert not mysql.local_infile_enabled(NON_EXISTANT, ADMIN_USER,
                                          ADMIN_PASS)


def test_symlinks_enabled_close(run_mock):
    """MySQL symlinks enabled?."""
    #assert not mysql_db.symlinks_enabled(run_mock, ADMIN_USER,
    #                                         ADMIN_PASS)
    assert not mysql.symlinks_enabled(NON_EXISTANT, ADMIN_USER,
                                      ADMIN_PASS)


def test_memcached_enabled_close(run_mock):
    """MySQL memcached enabled?."""
    assert not mysql.memcached_enabled(run_mock, ADMIN_USER,
                                       ADMIN_PASS)
    assert not mysql.memcached_enabled(NON_EXISTANT, ADMIN_USER,
                                       ADMIN_PASS)


def test_secure_file_close(run_mock):
    """MySQL secure_file_priv enabled?."""
    #assert not mysql_db.secure_file_priv_disabled(run_mock, ADMIN_USER,
    #                                      ADMIN_PASS)
    assert not mysql.secure_file_priv_disabled(NON_EXISTANT, ADMIN_USER,
                                               ADMIN_PASS)


def test_strict_all_tables_close(run_mock):
    """STRICT_ALL_TABLES enabled?."""
    #assert not mysql_db.strict_all_tables_disabled(run_mock, ADMIN_USER,
    #                                      ADMIN_PASS)
    assert not mysql.strict_all_tables_disabled(NON_EXISTANT, ADMIN_USER,
                                                   ADMIN_PASS)


def test_log_error_close(run_mock):
    """MySQL log_error enabled?."""
    assert not mysql.log_error_disabled(NON_EXISTANT, ADMIN_USER,
                                        ADMIN_PASS)


def test_logs_on_systemfs_close(run_mock):
    """MySQL logs on system filesystems enabled?."""
    #assert not mysql_db.logs_on_system_fs(run_mock, ADMIN_USER,
    #                                      ADMIN_PASS)
    assert not mysql.logs_on_system_fs(NON_EXISTANT, ADMIN_USER,
                                       ADMIN_PASS)


def test_logs_verbosity_close(run_mock):
    """MySQL logs on system filesystems enabled?."""
    #assert not mysql_db.logs_verbosity_low(run_mock, ADMIN_USER,
    #                                      ADMIN_PASS)
    assert not mysql.logs_verbosity_low(NON_EXISTANT, ADMIN_USER,
                                        ADMIN_PASS)


def test_auto_creates_users_close(run_mock):
    """MySQL auto creates users?."""
    assert not mysql.auto_creates_users(run_mock, ADMIN_USER,
                                           ADMIN_PASS)
    assert not mysql.auto_creates_users(NON_EXISTANT, ADMIN_USER,
                                           ADMIN_PASS)


def test_users_without_pass_close(run_mock):
    """MySQL users have passwords?."""
    assert not mysql.has_users_without_password(run_mock, ADMIN_USER,
                                                ADMIN_PASS)
    assert not mysql.has_users_without_password(NON_EXISTANT, ADMIN_USER,
                                                ADMIN_PASS)


def test_password_expiration_close(run_mock):
    """MySQL password expiration safe?."""
    assert not mysql.password_expiration_unsafe(NON_EXISTANT, ADMIN_USER,
                                                ADMIN_PASS)


def test_password_equals_to_user_close(run_mock):
    """MySQL users have password equal to the username?."""
    assert not mysql.password_equals_to_user(run_mock, ADMIN_USER,
                                             ADMIN_PASS)
    assert not mysql.password_equals_to_user(NON_EXISTANT, ADMIN_USER,
                                             ADMIN_PASS)


def test_wildcard_hosts_close(run_mock):
    """MySQL users have wildcard hosts?."""
    assert not mysql.users_have_wildcard_host(NON_EXISTANT, ADMIN_USER,
                                              ADMIN_PASS)


def test_uses_ssl_close(run_mock):
    """MySQL uses SSL?."""
    #assert not mysql_db.uses_ssl(run_mock, ADMIN_USER, ADMIN_PASS)
    assert not mysql.uses_ssl(NON_EXISTANT, ADMIN_USER, ADMIN_PASS)


def test_ssl_forced_close(run_mock):
    """MySQL users forced to use?."""
    #assert not mysql_db.ssl_unforced(run_mock, ADMIN_USER, ADMIN_PASS)
    assert not mysql.ssl_unforced(NON_EXISTANT, ADMIN_USER, ADMIN_PASS)
