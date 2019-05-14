# -*- coding: utf-8 -*-

"""This module allows to check generic MySQL/MariaDB DB vulnerabilities."""

# standard imports
from __future__ import absolute_import

# 3rd party imports
import mysql.connector

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track, level


class ConnError(Exception):
    """
    A connection error occurred.

    :py:exc:`mysql.connector.errors.InterfaceError` wrapper exception.
    """


def _get_mysql_cursor(server: str,
                      username: str,
                      password: str,
                      port: int) -> mysql.connector.MySQLConnection:
    """Get MySQL cursor."""
    try:
        mydb = mysql.connector.connect(
            host=server,
            user=username,
            passwd=password,
            port=port
        )
    except (mysql.connector.errors.InterfaceError,
            mysql.connector.errors.ProgrammingError) as exc:
        raise ConnError(exc)
    else:
        return mydb


@level('low')
@track
def have_access(server: str, username: str, password: str,
                port: int = 3306) -> bool:
    """Check if there is access to database server."""
    result = True
    try:
        _get_mysql_cursor(server, username, password, port)
    except ConnError as exc:
        show_unknown('Not access to server',
                     details=dict(server=server, user=username,
                                  error=str(exc)))
        result = False
    else:
        show_open('Access to server verified',
                  details=dict(server=server))
    return result


@level('low')
@track
def test_db_exists(server: str, username: str, password: str,
                   port: int = 3306) -> bool:
    """Check if "test" database exists."""
    try:
        mydb = _get_mysql_cursor(server, username, password, port)
    except ConnError as exc:
        show_unknown('There was an error connecting to MySQL engine',
                     details=dict(server=server, user=username,
                                  error=str(exc)))
        return False
    else:
        mycursor = mydb.cursor()

        mycursor.execute("SHOW DATABASES")

        result = ('test',) in list(mycursor)

        if result:
            show_open('Database "test" is present',
                      details=dict(server=server))
        else:
            show_close('Database "test" not present',
                       details=dict(server=server))
        return result


@level('medium')
@track
def local_infile_enabled(server: str, username: str, password: str,
                         port: int = 3306) -> bool:
    """Check if 'local_infile' parameter is set to ON."""
    try:
        mydb = _get_mysql_cursor(server, username, password, port)
    except ConnError as exc:
        show_unknown('There was an error connecting to MySQL engine',
                     details=dict(server=server, user=username,
                                  error=str(exc)))
        return False
    else:
        mycursor = mydb.cursor()

        query = "SHOW VARIABLES WHERE Variable_name = 'local_infile'"
        mycursor.execute(query)

        result = ('local_infile', 'ON') in list(mycursor)

        if result:
            show_open('Parameter "local_infile" is ON on server',
                      details=dict(server=server))
        else:
            show_close('Parameter "local_infile" is OFF on server',
                       details=dict(server=server))
        return result


@level('low')
@track
def symlinks_enabled(server: str, username: str, password: str,
                     port: str = 3306) -> bool:
    """Check if symbolic links are enabled on MySQL server."""
    try:
        mydb = _get_mysql_cursor(server, username, password, port)
    except ConnError as exc:
        show_unknown('There was an error connecting to MySQL engine',
                     details=dict(server=server, user=username,
                                  error=str(exc)))
        return False
    else:
        mycursor = mydb.cursor()

        query = "SHOW variables LIKE 'have_symlink'"
        mycursor.execute(query)

        result = ('have_symlink', 'DISABLED') not in list(mycursor)

        if result:
            show_open('Symbolic links are supported by server',
                      details=dict(server=server))
        else:
            show_close('Symbolic links are not supported by server',
                       details=dict(server=server))
        return result


@level('low')
@track
def memcached_enabled(server: str, username: str, password: str,
                      port: str = 3306) -> bool:
    """Check if memcached daemon is enabled on server."""
    try:
        mydb = _get_mysql_cursor(server, username, password, port)
    except ConnError as exc:
        show_unknown('There was an error connecting to MySQL engine',
                     details=dict(server=server, user=username,
                                  error=str(exc)))
        return False
    else:
        mycursor = mydb.cursor()

        query = "SELECT * FROM information_schema.plugins WHERE \
PLUGIN_NAME='daemon_memcached'"
        mycursor.execute(query)

        result = len(list(mycursor)) != 0

        if result:
            show_open('Memcached daemon enabled on server',
                      details=dict(server=server))
        else:
            show_close('Memcached daemon not enabled on server',
                       details=dict(server=server))
        return result


@level('medium')
@track
def secure_file_priv_disabled(server: str, username: str,
                              password: str, port: int = 3306) -> bool:
    """Check if secure_file_priv is configured on server."""
    try:
        mydb = _get_mysql_cursor(server, username, password, port)
    except ConnError as exc:
        show_unknown('There was an error connecting to MySQL engine',
                     details=dict(server=server, user=username,
                                  error=str(exc)))
        return False
    else:
        mycursor = mydb.cursor()

        query = "SHOW GLOBAL VARIABLES WHERE \
Variable_name = 'secure_file_priv' AND Value<>''"
        mycursor.execute(query)

        result = len(list(mycursor)) == 0

        if result:
            show_open('Parameter "secure_file_priv" not established',
                      details=dict(server=server))
        else:
            show_close('Parameter "secure_file_priv" is established',
                       details=dict(server=server))
        return result


@level('medium')
@track
def strict_all_tables_disabled(server: str, username: str,
                               password: str, port: int = 3306) -> bool:
    """Check if STRICT_ALL_TABLES is enabled on MySQL server."""
    try:
        mydb = _get_mysql_cursor(server, username, password, port)
    except ConnError as exc:
        show_unknown('There was an error connecting to MySQL engine',
                     details=dict(server=server, user=username,
                                  error=str(exc)))
        return False
    else:
        mycursor = mydb.cursor()

        query = "SHOW VARIABLES LIKE 'sql_mode'"
        mycursor.execute(query)

        result = 'STRICT_ALL_TABLES' not in list(mycursor)[0][1]

        if result:
            show_open('STRICT_ALL_TABLES not enabled on by server',
                      details=dict(server=server))
        else:
            show_close('STRICT_ALL_TABLES enabled on by server',
                       details=dict(server=server))
        return result


@level('medium')
@track
def log_error_disabled(server: str, username: str, password: str,
                       port: int = 3306) -> bool:
    """Check if 'log_error' parameter is set on MySQL server."""
    try:
        mydb = _get_mysql_cursor(server, username, password, port)
    except ConnError as exc:
        show_unknown('There was an error connecting to MySQL engine',
                     details=dict(server=server, user=username,
                                  error=str(exc)))
        return False
    else:
        mycursor = mydb.cursor()

        query = "SHOW variables LIKE 'log_error'"
        mycursor.execute(query)

        result = ('log_error', '') in list(mycursor)

        if result:
            show_open('Parameter "log_error" not set on server',
                      details=dict(server=server))
        else:
            show_close('Parameter "log_error" is set on server',
                       details=dict(server=server))
        return result


@level('medium')
@track
def logs_on_system_fs(server: str, username: str, password: str,
                      port: int = 3306) -> bool:
    """Check if logs are stored on a system filesystem on server."""
    try:
        mydb = _get_mysql_cursor(server, username, password, port)
    except ConnError as exc:
        show_unknown('There was an error connecting to MySQL engine',
                     details=dict(server=server, user=username,
                                  error=str(exc)))
        return False
    else:
        mycursor = mydb.cursor()

        query = "SELECT @@global.log_bin_basename"
        mycursor.execute(query)

        _result = list(mycursor)[0][0]
        result = _result.startswith('/var') or _result.startswith('/usr')

        if result:
            show_open('Logs are stored on system filesystems on server',
                      details=dict(server=server))
        else:
            show_close('Logs are outside system filesystems on server',
                       details=dict(server=server))
        return result


@level('low')
@track
def logs_verbosity_low(server: str, username: str, password: str,
                       port: int = 3306) -> bool:
    """Check if logs verbosity includes errors, warnings and notes."""
    try:
        mydb = _get_mysql_cursor(server, username, password, port)
    except ConnError as exc:
        show_unknown('There was an error connecting to MySQL engine',
                     details=dict(server=server, user=username,
                                  error=str(exc)))
        return False
    else:
        mycursor = mydb.cursor()

        query = "SHOW GLOBAL VARIABLES LIKE 'log_error_verbosity'"
        mycursor.execute(query)

        if list(mycursor):
            verbosity = list(mycursor)[0][1]
            result = verbosity not in ('2', '3')
        else:
            verbosity = 'empty'
            result = True

        if result:
            show_open('Logs verbosity not enough',
                      details=dict(server=server, verbosity=verbosity))
        else:
            show_close('Logs verbosity is sufficient',
                       details=dict(server=server, verbosity=verbosity))
        return result


@level('high')
@track
def auto_creates_users(server: str, username: str, password: str,
                       port: int = 3306) -> bool:
    """Check if 'NO_AUTO_CREATE_USER' param is set."""
    try:
        mydb = _get_mysql_cursor(server, username, password, port)
    except ConnError as exc:
        show_unknown('There was an error connecting to MySQL engine',
                     details=dict(server=server, user=username,
                                  error=str(exc)))
        return False
    else:
        mycursor = mydb.cursor()

        queries = ['SELECT @@global.sql_mode', 'SELECT @@session.sql_mode']
        result = False
        for query in queries:
            mycursor.execute(query)

            _result = list(mycursor)[0][0]
            result = 'NO_AUTO_CREATE_USER' not in _result
            if result:
                break

        if result:
            show_open('Param "NO_AUTO_CREATE_USER" not set on server',
                      details=dict(server=server))
        else:
            show_close('Param "NO_AUTO_CREATE_USER" is set on server',
                       details=dict(server=server))
        return result


@level('high')
@track
def has_users_without_password(server: str, username: str,
                               password: str, port: int = 3306) -> bool:
    """Check if users have a password set."""
    try:
        mydb = _get_mysql_cursor(server, username, password, port)
    except ConnError as exc:
        show_unknown('There was an error connecting to MySQL engine',
                     details=dict(server=server, user=username,
                                  error=str(exc)))
        return False
    else:
        mycursor = mydb.cursor()

        query = 'select user from mysql.user where password=""'
        mycursor.execute(query)

        _result = list(mycursor)
        result = len(_result) != 0

        if result:
            show_open('There are users without password on server',
                      details=dict(server=server,
                                   users=", ".join([x[0].decode()
                                                    for x in _result])))
        else:
            show_close('All users have passwords on server',
                       details=dict(server=server))
        return result


@level('high')
@track
def password_expiration_unsafe(server: str, username: str,
                               password: str, port: int = 3306) -> bool:
    """Check if password expiration time is safe."""
    try:
        mydb = _get_mysql_cursor(server, username, password, port)
    except ConnError as exc:
        show_unknown('There was an error connecting to MySQL engine',
                     details=dict(server=server, user=username,
                                  error=str(exc)))
        return False
    else:
        mycursor = mydb.cursor()

        query = 'SHOW VARIABLES LIKE "default_password_lifetime"'
        mycursor.execute(query)

        _result = list(mycursor)
        if not _result:
            result = True
        elif int(_result[0][1]) > 90:
            result = True
        else:
            result = False

        if result:
            show_open('Password lifetime is unsafe',
                      details=dict(server=server))

        else:
            show_close('Password lifetime is safe',
                       details=dict(server=server))
        return result


@level('high')
@track
def password_equals_to_user(server: str, username: str,
                            password: str, port: int = 3006) -> bool:
    """Check if users' password is the same username."""
    try:
        mydb = _get_mysql_cursor(server, username, password, port)
    except ConnError as exc:
        show_unknown('There was an error connecting to MySQL engine',
                     details=dict(server=server, user=username,
                                  error=str(exc)))
        return False
    else:
        mycursor = mydb.cursor()

        query = 'SELECT User,password FROM mysql.user \
WHERE BINARY password=CONCAT("*", UPPER(SHA1(UNHEX(SHA1(user)))))'
        mycursor.execute(query)

        _result = list(mycursor)
        result = len(_result) != 0

        if result:
            show_open('There are users with the password=username',
                      details=dict(server=server,
                                   users=", ".join([x[0].decode()
                                                    for x in _result])))
        else:
            show_close('All users have passwords different to the username',
                       details=dict(server=server))
        return result


@level('high')
@track
def users_have_wildcard_host(server: str, username: str,
                             password: str, port: int = 3306) -> bool:
    """Check if users have a wildcard host grants."""
    try:
        mydb = _get_mysql_cursor(server, username, password, port)
    except ConnError as exc:
        show_unknown('There was an error connecting to MySQL engine',
                     details=dict(server=server, user=username,
                                  error=str(exc)))
        return False
    else:
        mycursor = mydb.cursor()

        query = 'SELECT user FROM mysql.user WHERE host = "%"'
        mycursor.execute(query)

        _result = list(mycursor)
        result = len(_result) != 0

        if result:
            show_open('There are users with wildcard hosts',
                      details=dict(server=server,
                                   users=", ".join([x[0].decode()
                                                    for x in _result])))
        else:
            show_close('There are not users with wildcard hosts',
                       details=dict(server=server))
        return result


@level('high')
@track
def not_use_ssl(server: str, username: str, password: str,
                port: int = 3306) -> bool:
    """Check if MySQL server uses SSL."""
    try:
        mydb = _get_mysql_cursor(server, username, password, port)
    except ConnError as exc:
        show_unknown('There was an error connecting to MySQL engine',
                     details=dict(server=server, user=username,
                                  error=str(exc)))
        return False
    else:
        mycursor = mydb.cursor()

        query = 'SHOW variables WHERE variable_name = "have_ssl"'
        mycursor.execute(query)

        _result = list(mycursor)
        result = _result[0][1] == 'DISABLED'

        if result:
            show_open('Server don\'t use SSL',
                      details=dict(server=server))
        else:
            show_close('Server uses SSL',
                       details=dict(server=server))
        return result


@level('high')
@track
def ssl_unforced(server: str, username: str, password: str,
                 port: int = 3306) -> bool:
    """Check if users are forced to use SSL."""
    try:
        mydb = _get_mysql_cursor(server, username, password, port)
    except ConnError as exc:
        show_unknown('There was an error connecting to MySQL engine',
                     details=dict(server=server, user=username,
                                  error=str(exc)))
        return False
    else:
        mycursor = mydb.cursor()

        query = 'SELECT user, ssl_type FROM mysql.user WHERE NOT HOST \
IN ("::1", "127.0.0.1", "localhost") AND \
NOT ssl_type IN ("ANY", "X509", "SPECIFIED")'
        mycursor.execute(query)

        _result = list(mycursor)
        result = len(_result) != 0

        if result:
            show_open('Users are not forced to use SSL',
                      details=dict(server=server,
                                   users=", ".join([x[0].decode()
                                                    for x in _result])))
        else:
            show_close('Users are forced to use SSL',
                       details=dict(server=server))
        return result
