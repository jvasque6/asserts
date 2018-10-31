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


#
# Open tests
#


@pytest.mark.parametrize('get_mock_ip', ['mysql_db_weak'], indirect=True)
def test_test_db_present_open(get_mock_ip):
    """MySQL 'test' DB present?."""
    assert mysql.test_db_exists(get_mock_ip, ADMIN_USER, ADMIN_PASS)


@pytest.mark.parametrize('get_mock_ip', ['mysql_db_weak'], indirect=True)
def test_local_infile_open(get_mock_ip):
    """MySQL 'local_infile' on?."""
    assert mysql.local_infile_enabled(get_mock_ip, ADMIN_USER, ADMIN_PASS)


@pytest.mark.parametrize('get_mock_ip', ['mysql_db_weak'], indirect=True)
def test_symlinks_enabled_open(get_mock_ip):
    """MySQL symlinks enabled?."""
    assert mysql.symlinks_enabled(get_mock_ip, ADMIN_USER, ADMIN_PASS)


@pytest.mark.parametrize('get_mock_ip', ['mysql_db_weak'], indirect=True)
def test_secure_file_open(get_mock_ip):
    """MySQL secure_file_priv enabled?."""
    assert mysql.secure_file_priv_disabled(get_mock_ip, ADMIN_USER,
                                           ADMIN_PASS)


@pytest.mark.parametrize('get_mock_ip', ['mysql_db_weak'], indirect=True)
def test_strict_all_tables_open(get_mock_ip):
    """STRICT_ALL_TABLES enabled?."""
    assert mysql.strict_all_tables_disabled(get_mock_ip, ADMIN_USER,
                                            ADMIN_PASS)


@pytest.mark.parametrize('get_mock_ip', ['mysql_db_weak'], indirect=True)
def test_log_error_open(get_mock_ip):
    """MySQL log_error enabled?."""
    assert mysql.log_error_disabled(get_mock_ip, ADMIN_USER,
                                       ADMIN_PASS)


@pytest.mark.parametrize('get_mock_ip', ['mysql_db_weak'], indirect=True)
def test_logs_on_systemfs_open(get_mock_ip):
    """MySQL logs on system filesystems enabled?."""
    assert mysql.logs_on_system_fs(get_mock_ip, ADMIN_USER,
                                   ADMIN_PASS)


@pytest.mark.parametrize('get_mock_ip', ['mysql_db_weak'], indirect=True)
def test_logs_verbosity_open(get_mock_ip):
    """MySQL verbosity enough?."""
    assert mysql.logs_verbosity_low(get_mock_ip, ADMIN_USER,
                                    ADMIN_PASS)


@pytest.mark.parametrize('get_mock_ip', ['mysql_db_weak'], indirect=True)
def test_password_expiration_open(get_mock_ip):
    """MySQL password expiration safe?."""
    assert mysql.password_expiration_unsafe(get_mock_ip, ADMIN_USER,
                                            ADMIN_PASS)


@pytest.mark.parametrize('get_mock_ip', ['mysql_db_weak'], indirect=True)
def test_wildcard_hosts_open(get_mock_ip):
    """MySQL users have wildcard hosts?."""
    assert mysql.users_have_wildcard_host(get_mock_ip, ADMIN_USER,
                                          ADMIN_PASS)


@pytest.mark.parametrize('get_mock_ip', ['mysql_db_weak'], indirect=True)
def test_uses_ssl_open(get_mock_ip):
    """MySQL uses SSL?."""
    assert mysql.uses_ssl(get_mock_ip, ADMIN_USER, ADMIN_PASS)


@pytest.mark.parametrize('get_mock_ip', ['mysql_db_weak'], indirect=True)
def test_ssl_forced_open(get_mock_ip):
    """MySQL users forced to use?."""
    assert mysql.ssl_unforced(get_mock_ip, ADMIN_USER, ADMIN_PASS)
