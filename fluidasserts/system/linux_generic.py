# -*- coding: utf-8 -*-
"""
Linux OS module.

This module allows to check Linux vulnerabilities.
"""

# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.helper.ssh_helper import ssh_exec_command
from fluidasserts.utils.decorators import track


@track
def is_os_min_priv_disabled(server: str, username: str, password: str,
                            ssh_config: str = None) -> bool:
    """
    Check if ``umask`` or similar is secure in ``os_linux_generic``.

    :param server: URL or IP of host to test.
    :param username: User to connect to server.
    :param password: Password for given user.
    :param ssh_config: Path to SSH connection config file.
    """
    result = True
    cmd = 'umask'
    out, _ = ssh_exec_command(server, username, password, cmd,
                              ssh_config)

    if out == b'0027':
        show_close('{} server has secure default privileges'.
                   format(server), details=dict(umask=out.decode('utf-8')))
        result = False
    else:
        show_open('{} server has insecure default privileges'.
                  format(server), details=dict(umask=out.decode('utf-8')))
        result = True
    return result


@track
def is_os_sudo_disabled(server: str, username: str, password: str,
                        ssh_config: str = None) -> bool:
    """
    Check if there's ``sudo`` or similar installed in ``os_linux_generic``.

    :param server: URL or IP of host to test.
    :param username: User to connect to server.
    :param password: Password for given user.
    :param ssh_config: Path to SSH connection config file.
    """
    result = True
    cmd = 'which sudo'
    out, _ = ssh_exec_command(server, username, password, cmd,
                              ssh_config)

    if out:
        show_close('{} server has sudo (or like) installed'.
                   format(server), details=dict(paths=out.decode('utf-8')))
        result = False
    else:
        show_open('{} server has not sudo (or like) installed'.
                  format(server), details=dict(paths=out.decode('utf-8')))
        result = True
    return result


@track
def is_os_compilers_installed(server: str, username: str, password: str,
                              ssh_config: str = None) -> bool:
    """
    Check if there is any compiler installed in ``os_linux_generic``.

    :param server: URL or IP of host to test.
    :param username: User to connect to server.
    :param password: Password for given user.
    :param ssh_config: Path to SSH connection config file.
    """
    result = True
    cmd = 'which cc gcc c++ g++ javac ld as nasm'
    out, _ = ssh_exec_command(server, username, password, cmd,
                              ssh_config)

    if not out:
        show_close('{} server has not compilers installed'.
                   format(server), details=dict(paths=out.decode('utf-8')))
        result = False
    else:
        show_open('{} server has compilers installed'.format(server),
                  details=dict(paths=out.decode('utf-8')))
        result = True
    return result


@track
def is_os_antimalware_not_installed(server: str, username: str, password: str,
                                    ssh_config: str = None) -> bool:
    """
    Check if there is any antimalware installed in ``os_linux_generic``.

    :param server: URL or IP of host to test.
    :param username: User to connect to server.
    :param password: Password for given user.
    :param ssh_config: Path to SSH connection config file.
    """
    result = True
    cmd = 'which clamscan avgscan'
    out, _ = ssh_exec_command(server, username, password, cmd,
                              ssh_config)

    if out:
        show_close('{} server has an antivirus installed'.format(server),
                   details=dict(paths=out.decode('utf-8')))
        result = False
    else:
        show_open('{} server has not an antivirus installed'.
                  format(server), details=dict(paths=out.decode('utf-8')))
        result = True
    return result


@track
def is_os_remote_admin_enabled(server: str, username: str, password: str,
                               ssh_config: str = None) -> bool:
    """
    Check if admins can remotely log into ``os_linux_generic``.

    :param server: URL or IP of host to test.
    :param username: User to connect to server.
    :param password: Password for given user.
    :param ssh_config: Path to SSH connection config file.
    """
    result = True
    cmd = 'grep -i "^PermitRootLogin.*yes" /etc/ssh/sshd_config'
    out, _ = ssh_exec_command(server, username, password, cmd,
                              ssh_config)

    if not out:
        show_close('{} server has not remote admin login enabled'.
                   format(server), details=dict(result=out.decode('utf-8')))
        result = False
    else:
        show_open('{} server has remote admin login enabled'.
                  format(server), details=dict(result=out.decode('utf-8')))
        result = True
    return result


@track
def is_os_syncookies_disabled(server: str, username: str, password: str,
                              ssh_config: str = None) -> bool:
    """
    Check if ``SynCookies`` or similar is enabled in ``os_linux_generic``.

    :param server: URL or IP of host to test.
    :param username: User to connect to server.
    :param password: Password for given user.
    :param ssh_config: Path to SSH connection config file.
    """
    result = True
    cmd = 'sysctl -q -n net.ipv4.tcp_syncookies'
    out, _ = ssh_exec_command(server, username, password, cmd,
                              ssh_config)

    if out == b'1':
        show_close('{} server has syncookies enabled'.
                   format(server), details=dict(result=out.decode('utf-8')))
        result = False
    else:
        show_open('{} server has syncookies disabled'.
                  format(server), details=dict(result=out.decode('utf-8')))
        result = True
    return result
