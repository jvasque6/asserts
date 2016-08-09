# -*- coding: utf-8 -*-

"""Modulo para verificación del protocolo SSH.

Este modulo permite verificar vulnerabilidades propias de SSH como:

    * SSH versión 1 activado,
    * Banner de seguridad inexistente,
    * Login conocido accesible,
    * Servicio activado innecesariamente,
"""

import paramiko


def login(host, username, password):
    ssh = paramiko.SSHClient()
    ssh.connect(host, username=username, password=password)
