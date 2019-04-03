# -*- coding: utf-8 -*-

"""This module allows to check generic Linux vulnerabilities."""

# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.helper.ssh import ssh_exec_command, ConnError
from fluidasserts.utils.decorators import track, level


@level('medium')
@track
def is_min_priv_disabled(server: str, username: str, password: str,
                         ssh_config: str = None) -> bool:
    """
    Check if ``umask`` or similar is secure in ``os_linux``.

    :param server: URL or IP of host to test.
    :param username: User to connect to server.
    :param password: Password for given user.
    :param ssh_config: Path to SSH connection config file.
    """
    result = True
    cmd = 'umask'
    try:
        out, _ = ssh_exec_command(server, username, password, cmd, ssh_config)
    except ConnError as exc:
        show_unknown('Could not connect',
                     details=dict(server=server, username=username,
                                  error=str(exc)))
        return False
    if out == b'0027':
        show_close('{} server has secure default privileges'.
                   format(server), details=dict(umask=out.decode('utf-8')))
        result = False
    else:
        show_open('{} server has insecure default privileges'.
                  format(server), details=dict(umask=out.decode('utf-8')))
        result = True
    return result


@level('medium')
@track
def is_sudo_disabled(server: str, username: str, password: str,
                     ssh_config: str = None) -> bool:
    """
    Check if there's ``sudo`` or similar installed in ``os_linux``.

    :param server: URL or IP of host to test.
    :param username: User to connect to server.
    :param password: Password for given user.
    :param ssh_config: Path to SSH connection config file.
    """
    result = True
    cmd = 'which sudo'
    try:
        out, _ = ssh_exec_command(server, username, password, cmd, ssh_config)
    except ConnError as exc:
        show_unknown('Could not connect',
                     details=dict(server=server, username=username,
                                  error=str(exc)))
        return False
    if out:
        show_close('{} server has "sudo" (or like) installed'.
                   format(server), details=dict(paths=out.decode('utf-8')))
        result = False
    else:
        show_open('{} server does not have "sudo" (or like) installed'.
                  format(server), details=dict(paths=out.decode('utf-8')))
        result = True
    return result


@level('medium')
@track
def are_compilers_installed(server: str, username: str, password: str,
                            ssh_config: str = None) -> bool:
    """
    Check if there is any compiler installed in ``os_linux``.

    :param server: URL or IP of host to test.
    :param username: User to connect to server.
    :param password: Password for given user.
    :param ssh_config: Path to SSH connection config file.
    """
    result = True
    cmd = 'which cc gcc c++ g++ javac ld as nasm'
    try:
        out, _ = ssh_exec_command(server, username, password, cmd, ssh_config)
    except ConnError as exc:
        show_unknown('Could not connect',
                     details=dict(server=server, username=username,
                                  error=str(exc)))
        return False
    if not out:
        show_close('{} server does not have compilers installed'.
                   format(server), details=dict(paths=out.decode('utf-8')))
        result = False
    else:
        show_open('{} server has compilers installed'.format(server),
                  details=dict(paths=out.decode('utf-8')))
        result = True
    return result


@level('medium')
@track
def is_antimalware_not_installed(server: str, username: str, password: str,
                                 ssh_config: str = None) -> bool:
    """
    Check if there is any antimalware installed in ``os_linux``.

    :param server: URL or IP of host to test.
    :param username: User to connect to server.
    :param password: Password for given user.
    :param ssh_config: Path to SSH connection config file.
    """
    result = True
    cmd = 'which clamscan avgscan'
    try:
        out, _ = ssh_exec_command(server, username, password, cmd, ssh_config)
    except ConnError as exc:
        show_unknown('Could not connect',
                     details=dict(server=server, username=username,
                                  error=str(exc)))
        return False
    if out:
        show_close('{} server has an antivirus installed'.format(server),
                   details=dict(paths=out.decode('utf-8')))
        result = False
    else:
        show_open('{} server does not have an antivirus installed'.
                  format(server), details=dict(paths=out.decode('utf-8')))
        result = True
    return result


@level('high')
@track
def is_remote_admin_enabled(server: str, username: str, password: str,
                            ssh_config: str = None) -> bool:
    """
    Check if admins can remotely log into ``os_linux``.

    :param server: URL or IP of host to test.
    :param username: User to connect to server.
    :param password: Password for given user.
    :param ssh_config: Path to SSH connection config file.
    """
    result = True
    cmd = 'grep -i "^PermitRootLogin.*yes" /etc/ssh/sshd_config'
    try:
        out, _ = ssh_exec_command(server, username, password, cmd, ssh_config)
    except ConnError as exc:
        show_unknown('Could not connect',
                     details=dict(server=server, username=username,
                                  error=str(exc)))
        return False
    if not out:
        show_close('{} server does not have remote admin login enabled'.
                   format(server), details=dict(result=out.decode('utf-8')))
        result = False
    else:
        show_open('{} server has remote admin login enabled'.
                  format(server), details=dict(result=out.decode('utf-8')))
        result = True
    return result


@level('low')
@track
def are_syncookies_disabled(server: str, username: str, password: str,
                            ssh_config: str = None) -> bool:
    """
    Check if ``SynCookies`` or similar is enabled in ``os_linux``.

    :param server: URL or IP of host to test.
    :param username: User to connect to server.
    :param password: Password for given user.
    :param ssh_config: Path to SSH connection config file.
    """
    result = True
    cmd = 'sysctl -q -n net.ipv4.tcp_syncookies'
    try:
        out, err = ssh_exec_command(server, username, password, cmd,
                                    ssh_config)
    except ConnError as exc:
        show_unknown('Could not connect',
                     details=dict(server=server, username=username,
                                  error=str(exc)))
        return False
    if err:
        show_unknown('Error checking', details=dict(error=err.decode('utf-8')))
        return False
    if out == b'1':
        show_close('{} server has syncookies enabled'.
                   format(server), details=dict(result=out.decode('utf-8')))
        result = False
    else:
        show_open('{} server has syncookies disabled'.
                  format(server), details=dict(result=out.decode('utf-8')))
        result = True
    return result
