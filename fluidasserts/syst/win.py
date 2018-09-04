# -*- coding: utf-8 -*-

"""This module allows to check Windows Server vulnerabilities."""

# standard imports
import re

# 3rd party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.helper.winrm_helper import winrm_exec_command, ConnError
from fluidasserts.utils.decorators import track


@track
def are_compilers_installed(server: str, username: str,
                            password: str) -> bool:
    """
    Check if there is any compiler installed in Windows Server.

    :param server: URL or IP of host to test.
    :param username: User to connect to WinRM.
    :param password: Password for given user.
    """
    common_compilers = ['Visual', 'Python', 'Mingw', 'CygWin']
    cmd = b'reg query \
"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall" /s'

    try:
        installed_software = winrm_exec_command(server, username, password,
                                                cmd)
    except ConnError as exc:
        show_unknown('Could not connect',
                     details=dict(server=server, username=username,
                                  error=str(exc)))
        return False
    installed_compilers = 0

    for compiler in common_compilers:
        if re.search(compiler, installed_software, re.IGNORECASE) is not None:
            installed_compilers = installed_compilers + 1

    result = True
    if installed_compilers > 0:
        show_open('{} server has compilers installed'.format(server),
                  details=dict(installed_software=installed_software))
        result = True
    else:
        show_close('{} server has no compilers installed'.format(server),
                   details=dict(installed_software=installed_software))
        result = False
    return result


@track
def is_antimalware_not_installed(server: str, username: str,
                                 password: str) -> bool:
    """
    Check if there is any antimalware installed in Windows Server.

    :param server: URL or IP of host to test.
    :param username: User to connect to WinRM.
    :param password: Password for given user.
    """
    common_av = ['Symantec', 'Norton', 'AVG', 'Kaspersky', 'TrendMicro',
                 'Panda', 'Sophos', 'McAfee', 'Eset']
    cmd = b'reg query \
"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall" /s'

    try:
        installed_software = winrm_exec_command(server, username, password,
                                                cmd)
    except ConnError as exc:
        show_unknown('Could not connect',
                     details=dict(server=server, username=username,
                                  error=str(exc)))
        return False
    installed_av = 0

    for antivirus in common_av:
        if re.search(antivirus, installed_software, re.IGNORECASE) is not None:
            installed_av = installed_av + 1

    result = True
    if installed_av > 0:
        show_close('{} server has an antivirus installed'.format(server),
                   details=dict(installed_software=installed_software))
        result = False
    else:
        show_open('{} server does not have an antivirus installed'
                  .format(server),
                  details=dict(installed_software=installed_software))
        result = True
    return result


@track
def are_syncookies_disabled(server: str) -> bool:
    """
    Check if SynCookies or similar is enabled in Windows Server.

    :param server: URL or IP of host to test.
    :param username: User to connect to WinRM.
    :param password: Password for given user.
    """
    # On Windows, SYN Cookies are enabled by default and there's no
    # way to disable it.
    show_close('Server has SYN Cookies enabled.', details=dict(server=server))
    return False


@track
def are_protected_users_disabled(server: str, username: str,
                                 password: str) -> bool:
    """
    Check if protected users is enabled on system.

    If the result is True, executing mimikatz would give dangerous results.

    :param server: URL or IP of host to test.
    :param username: User to connect to WinRM.
    :param password: Password for given user.
    """
    security_patches = ['KB2871997']
    cmd = b'reg query \
"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component\
Based Servicing\\Packages" /s'

    try:
        installed_software = winrm_exec_command(server, username, password,
                                                cmd)
    except ConnError as exc:
        show_unknown('Could not connect',
                     details=dict(server=server, username=username,
                                  error=str(exc)))
        return False
    installed_patches = 0

    for patch in security_patches:
        if re.search(patch, installed_software, re.IGNORECASE) is not None:
            installed_patches = installed_patches + 1

    result = True
    if installed_patches == len(security_patches):
        show_close('{} server has all required patches installed'.
                   format(server),
                   details=dict(security_patches=security_patches))
        result = False
    else:
        cmd = b'reg query \
"HKLM\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" \
/v UseLogonCredential'

        has_logon_credentials = winrm_exec_command(server, username,
                                                   password, cmd)
        if re.search('UseLogonCredential.*0x0', has_logon_credentials,
                     re.IGNORECASE) is not None:
            result = False
            show_close('{} server has UseLogonCredentials\
set to 0x0'.format(server))
        else:
            result = True
            show_open('{} server missing security patch'.format(server),
                      details=dict(security_patches=security_patches))
    return result
