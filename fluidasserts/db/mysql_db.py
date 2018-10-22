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
