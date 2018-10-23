# -*- coding: utf-8 -*-

"""This module allows to check generic MySQL DB vulnerabilities."""

# standard imports
# None

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

    pass


def _get_mysql_cursor(server: str,
                      username: str,
                      password: str) -> mysql.connector.MySQLConnection:
    """Get MySQL cursor."""
    try:
        mydb = mysql.connector.connect(
            host=server,
            user=username,
            passwd=password
        )
    except (mysql.connector.errors.InterfaceError,
            mysql.connector.errors.ProgrammingError) as exc:
        raise ConnError(exc)
    else:
        return mydb


@level('low')
@track
def test_db_exists(server: str, username: str, password: str) -> bool:
    """Check if "test" database exists."""
    try:
        mydb = _get_mysql_cursor(server, username, password)
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
def local_infile_enabled(server: str, username: str, password: str) -> bool:
    """Check if 'local_infile' parameter is set to ON."""
    try:
        mydb = _get_mysql_cursor(server, username, password)
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
            show_close('Parameter "local_infile" is ON on server',
                       details=dict(server=server))
        return result


@level('low')
@track
def symlinks_enabled(server: str, username: str, password: str) -> bool:
    """Check if symbolic links are enabled on MySQL server."""
    try:
        mydb = _get_mysql_cursor(server, username, password)
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
def memcached_enabled(server: str, username: str, password: str) -> bool:
    """Check if memcached daemon is enabled on server."""
    try:
        mydb = _get_mysql_cursor(server, username, password)
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
                              password: str) -> bool:
    """Check if secure_file_priv is configured on server."""
    try:
        mydb = _get_mysql_cursor(server, username, password)
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
                               password: str) -> bool:
    """Check if STRICT_ALL_TABLES is enabled on MySQL server."""
    try:
        mydb = _get_mysql_cursor(server, username, password)
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
def log_error_disabled(server: str, username: str, password: str) -> bool:
    """Check if 'log_error' parameter is set on MySQL server."""
    try:
        mydb = _get_mysql_cursor(server, username, password)
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
def logs_on_system_fs(server: str, username: str, password: str) -> bool:
    """Check if logs are stored on a system filesystem on server."""
    try:
        mydb = _get_mysql_cursor(server, username, password)
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
