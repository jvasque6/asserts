# -*- coding: utf-8 -*-

"""Modulo para verificacion del protocolo SSH."""

# standard imports
import os

# 3rd party imports
import paramiko

# local imports
# none


# pylint: disable=R0914
def ssh_user_pass(server, username, password, command):
    """Connect using SSH user and pass and exec specific command."""
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    out = False
    err = False
    try:
        ssh.connect(server, username=username, password=password)
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command)
        ssh_stdin.close()
        out = ssh_stdout.read()[:-1]
        err = ssh_stderr.read()[:-1]
    except paramiko.SSHException:
        raise
    finally:
        ssh.close()
    return out, err


def ssh_with_config(server, username, config_file, command):
    """Connect using SSH config and exec specific command."""
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

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
    except paramiko.SSHException:
        raise
    finally:
        ssh.close()
    return out, err


def ssh_exec_command(server, username, password, command,
                     config_file=None):
    """Connect using SSH and exec specific command."""
    if config_file is None:
        out, err = ssh_user_pass(server, username, password, command)
    else:
        out, err = ssh_with_config(server, username,
                                   config_file,
                                   command)
    return out, err
