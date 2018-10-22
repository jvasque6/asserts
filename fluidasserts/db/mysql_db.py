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
from fluidasserts.utils.decorators import track


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


@track
def local_infile_enabled(server: str, username: str, password: str) -> bool:
    """Check if "local_infile" parameter is set to ON."""
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
