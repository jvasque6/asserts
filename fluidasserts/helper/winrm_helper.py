# -*- coding: utf-8 -*-

"""
WinRM helper.

This must be run on the target server:
winrm qc
winrm get winrm/config/service
winrm set winrm/config/service @{AllowUnencrypted="true"}
winrm set winrm/config/service/auth @{Basic="true"}
winrm set winrm/config/client/auth @{Basic="true"}
"""

# standard imports
# None

# 3rd party imports
import winrm

# local imports
# none


def winrm_exec_command(server: str, username: str, password: str,
                       command: str) -> str:
    """
    Connect to WinRM execute a specific command.

    :param server: URL or IP of host to test.
    :param username: User to connect to WinRM.
    :param password: Password for given user.
    :param command: Command to execute in WinRM Session.
    """
    try:
        session = winrm.Session(server, auth=(username, password))
        result = session.run_cmd(command)
    except winrm.exceptions.WinRMTransportError:
        raise

    return result.std_out
