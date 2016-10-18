# -*- coding: utf-8 -*-
"""
Modulo OS os_linux_generic
"""

# standard imports
import logging
import os

# 3rd party imports
import paramiko

# local imports
# None


def ssh_user_pass(server, username, password, command):
    """
    Connects using SSH user and pass and exec specific command
    """
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
    """
    Connects using SSH config and exec specific command
    """
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
    """
    Connects using SSH and exec specific command
    """

    if config_file is None:
        out, err = ssh_user_pass(server, username, password, command)
    else:
        out, err = ssh_with_config(server, username,
                                   config_file,
                                   command)
    return out, err


def is_os_min_priv_enabled(server, username, password, ssh_config=None):
    """
    Checks if umask or similar is secure in os_linux_generic
    """
    result = True
    cmd = 'umask'
    out, _ = ssh_exec_command(server, username, password, cmd,
                              ssh_config)

    if out is '0027':
        logging.info('%s server has secure default privileges,\
                      Details=umask %s, %s', server, out, 'CLOSE')
        result = False
    else:
        logging.info('%s server has too open default privileges,\
                      Details=umask %s, %s', server, out, 'OPEN')
        result = True
    return result


def is_os_sudo_enabled(server, username, password, ssh_config=None):
    """
    Checks if there's sudo or similar installed in os_linux_generic
    """
    result = True
    cmd = 'which sudo'
    out, _ = ssh_exec_command(server, username, password, cmd,
                                ssh_config)

    if len(out) > 0:
        logging.info('%s server has sudo (or like) installed,\
                      Details=%s, %s', server, out, 'CLOSE')
        result = False
    else:
        logging.info('%s server has not sudo (or like) installed,\
                      Details=%s, %s', server, out, 'OPEN')
        result = True
    return result


def is_os_compilers_installed(server, username, password,
                              ssh_config=None):
    """
    Checks if there's any compiler installed in os_linux_generic
    """
    result = True
    cmd = 'which cc gcc c++ g++ javac ld as nasm'
    out, _ = ssh_exec_command(server, username, password, cmd,
                              ssh_config)

    if len(out) == 0:
        logging.info('%s server has not compilers installed,\
                      Details=%s, %s', server, out, 'CLOSE')
        result = False
    else:
        logging.info('%s server has compilers installed,\
                      Details=%s, %s', server, out, 'OPEN')
        result = True
    return result


def is_os_antimalware_installed(server, username, password,
                                ssh_config=None):
    """
    Checks if there's any antimalware installed in os_linux_generic
    """
    result = True
    cmd = 'which clamscan avgscan'
    out, err = ssh_exec_command(server, username, password, cmd,
                                ssh_config)

    if len(out) > 0:
        logging.info('%s server has an antivirus installed,\
                      Details=%s, %s', server, out, 'CLOSE')
        result = False
    else:
        logging.info('%s server has not an antivirus installed,\
                      Details=%s, %s', server, out, 'OPEN')
        result = True
    return result


def is_os_remote_admin_enabled(server, username, password,
                               ssh_config=None):
    """
    Checks if admins can remotely login in os_linux_generic
    """
    result = True
    cmd = 'grep -i "^PermitRootLogin.*yes" /etc/ssh/sshd_config'
    out, _ = ssh_exec_command(server, username, password, cmd,
                              ssh_config)

    if len(out) == 0:
        logging.info('%s server has not remote admin login enabled,\
                      Details=%s, %s', server, out, 'CLOSE')
        result = False
    else:
        logging.info('%s server has remote admin login enabled,\
                      Details=%s, %s', server, out, 'OPEN')
        result = True
    return result


def is_os_syncookies_enabled(server, username, password,
                             ssh_config=None):
    """
    Checks if SynCookies or similar is enabled in os_linux_generic
    """
    result = True
    cmd = 'cat /proc/sys/net/ipv4/tcp_syncookies'
    out, _ = ssh_exec_command(server, username, password, cmd,
                              ssh_config)

    if int(out) == 1:
        logging.info('%s server has syncookies enabled,\
                      Details=%s, %s', server, out, 'CLOSE')
        result = False
    else:
        logging.info('%s server has syncookies disabled,\
                      Details=%s, %s', server, out, 'OPEN')
        result = True
    return result
