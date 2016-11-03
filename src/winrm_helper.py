# -*- coding: utf-8 -*-

"""Modulo para verificación del protocolo WinRM.

Se debe ejecutar en el servidor:
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


def winrm_exec_command(server, username, password, command):
    """
    Connects using WinRM user and pass and exec specific command
    """
    try:
        session = winrm.Session(server, auth=(username, password))
        result = session.run_cmd(command)
    except winrm.exceptions.WinRMTransportError:
        raise

    return result.std_out
