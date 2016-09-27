# -*- coding: utf-8 -*-

"""Modulo para verificación del protocolo SSH.

Este modulo permite verificar vulnerabilidades propias de SSH como:

    * SSH versión 1 activado,
    * Banner de seguridad inexistente,
    * Login conocido accesible,
    * Servicio activado innecesariamente,
"""

# standard imports
# none

# 3rd party imports
import paramiko

# local imports
# none


def login(host, username, password):
    """Autenticación usando método de credenciales."""
    ssh = paramiko.SSHClient()
    ssh.connect(host, username=username, password=password)
