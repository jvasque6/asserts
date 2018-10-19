# -*- coding: utf-8 -*-

"""
SSH helper.

This module enables connections via SSH.
"""

# standard imports
import os
from typing import Tuple

# 3rd party imports
import paramiko

# local imports
# none


class ConnError(Exception):
    """
    A connection error occurred.

    :py:exc:`paramiko.ssh_exception.AuthenticationException` wrapper exception.
    """

    pass


def build_ssh_object() -> paramiko.client.SSHClient:
    """Build a Paramiko SSHClient object."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    return ssh


# pylint: disable=R0914
def ssh_user_pass(server: str, username: str, password: str,
                  command: str) -> Tuple[bool, bool]:
    """
    Connect using SSH username and password and execute given command.

    :param server: URL or IP of host to test.
    :param username: User to connect to server.
    :param password: Password for given user.
    :param command: Command to execute in SSH Session.
    """
    ssh = build_ssh_object()

    out = False
    err = False
    try:
        ssh.connect(server, username=username, password=password)
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command)
        ssh_stdin.close()
        out = ssh_stdout.read()[:-1]
        err = ssh_stderr.read()[:-1]
    except (paramiko.ssh_exception.NoValidConnectionsError,
            paramiko.ssh_exception.AuthenticationException) as exc:
        raise ConnError(exc)
    finally:
        ssh.close()
    return out, err


def ssh_with_config(server: str, username: str, config_file: str,
                    command: str) -> Tuple[bool, bool]:
    """
    Connect using SSH configuration file and execute given command.

    :param server: URL or IP of host to test.
    :param username: User to connect to server.
    :param config_file: Path to SSH connection config file.
    :param command: Command to execute in SSH Session.
    """
    ssh = build_ssh_object()

    out = False
    err = False
    try:
        ssh_config = paramiko.SSHConfig()
        user_config_file = os.path.expanduser(config_file)
        if os.path.exists(user_config_file):
            with open(user_config_file) as ssh_file:
                ssh_config.parse(ssh_file)

        user_config = ssh_config.lookup(server)

        rsa_key_file = os.path.expanduser(user_config['identityfile'][0])
        if os.path.exists(rsa_key_file):
            pkey = paramiko.RSAKey.from_private_key_file(rsa_key_file)

        cfg = {'hostname': server, 'username': username, 'pkey': pkey}

        for k in ('hostname', 'username', 'port'):
            if k in user_config:
                cfg[k] = user_config[k]

        ssh.connect(**cfg)
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command)
        ssh_stdin.close()
        out = ssh_stdout.read()[:-1]
        err = ssh_stderr.read()[:-1]
    except paramiko.SSHException as exc:
        raise ConnError(exc)
    finally:
        ssh.close()
    return out, err


def ssh_exec_command(server: str, username: str, password: str, command: str,
                     config_file: str = None) -> Tuple[bool, bool]:
    """
    Connect using SSH and execute specific command.

    :param server: URL or IP of host to test.
    :param username: User to connect to server.
    :param password: Password for given user.
    :param command: Command to execute in SSH Session.
    :param config_file: Path to SSH connection config file.
    """
    if config_file is None:
        out, err = ssh_user_pass(server, username, password, command)
    else:
        out, err = ssh_with_config(server, username, config_file, command)
    return out, err
