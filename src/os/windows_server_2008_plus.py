# -*- coding: utf-8 -*-
"""
Modulo OS Windows Server
"""

# standard imports
import logging
import re

# 3rd party imports
# None

# local imports
from fluidasserts.helper.winrm_helper import winrm_exec_command


def is_os_min_priv_disabled(server, username, password, ssh_config):
    """
    Checks if umask or similar is secure in Windows Server
    """
    pass


def is_os_sudo_disabled(server, username, password, ssh_config):
    """
    Checks if there's sudo or similar installed in Windows Server
    """
    pass


def is_os_compilers_installed(server, username, password, ssh_config):
    """
    Checks if there's any compiler installed in Windows Server
    """
    common_compilers = ['Visual', 'Python', 'Mingw', 'CygWin']
    cmd = b'reg query \
           "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall" /s'

    installed_software = winrm_exec_command(server,
                                            username,
                                            password,
                                            cmd)

    installed_compilers = 0

    # I'm sure there's a better way to do this
    for compiler in common_compilers:
        if re.search(compiler, installed_software,
                     re.IGNORECASE) is not None:
            installed_compilers = installed_compilers + 1

    result = True
    if installed_compilers > 0:
        logging.info('%s server has compilers installed,\
                     Details=%s, %s', server,
                     installed_software, 'OPEN')
        result = True
    else:
        logging.info('%s server has not compilers installed,\
                     Details=%s, %s', server,
                     installed_software, 'CLOSE')
        result = False
    return result


def is_os_antimalware_not_installed(server, username, password, ssh_config):
    """
    Checks if there's any antimalware installed in Windows Server
    """
    common_av = ['Symantec', 'Norton', 'AVG', 'Kaspersky', 'TrendMicro',
                 'Panda', 'Sophos', 'McAfee', 'Eset']
    cmd = b'reg query \
           "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall" /s'
    installed_software = winrm_exec_command(server,
                                            username,
                                            password,
                                            cmd)

    installed_av = 0

    # I'm sure there's a better way to do this
    for antivirus in common_av:
        if re.search(antivirus, installed_software,
                     re.IGNORECASE) is not None:
            installed_av = installed_av + 1

    result = True
    if installed_av > 0:
        logging.info('%s server has an antivirus installed,\
                     Details=%s, %s', server,
                     installed_software, 'CLOSE')
        result = False
    else:
        logging.info('%s server has not an antivirus installed,\
                     Details=%s, %s', server,
                     installed_software, 'OPEN')
        result = True
    return result


def is_os_remote_admin_enabled(server, username, password, ssh_config):
    """
    Checks if admins can remotely login in Windows Server
    """
    pass


def is_os_syncookies_disabled(server, username, password, ssh_config):
    """
    Checks if SynCookies or similar is enabled in Windows Server
    """

    # On Windows, SYN Cookies are enabled by default and there's no
    # way to disable it.
    logging.info('%s server has SYN Cookies enabled,\
                     Details=%s', server, 'CLOSE')
    return False


def is_protected_users_disabled(server, username, password):
    """
    Checks if protected users is enabled on system.
    If the result is True, executing mimikatz would give
    dangerous results.
    """
    security_patches = ['KB2871997']
    cmd = b'reg query \
           "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\\\
           Component Based Servicing\Packages" /s'

    installed_software = winrm_exec_command(server,
                                            username,
                                            password,
                                            cmd)

    installed_patches = 0

    # I'm sure there's a better way to do this
    for patch in security_patches:
        if re.search(patch, installed_software,
                     re.IGNORECASE) is not None:
            installed_patches = installed_patches + 1

    result = True
    if installed_patches == len(security_patches):
        logging.info('%s server has all required patches installed,\
                     Details=%s, %s', server,
                     ",".join(security_patches), 'CLOSE')
        result = False
    else:
        cmd = b'reg query \
                "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential'

        has_logon_credentials = winrm_exec_command(server,
                                                   username,
                                                   password,
                                                   cmd)
        if re.search('UseLogonCredential.*0x0',
                     has_logon_credentials,
                     re.IGNORECASE) is not None:
                         result = False
                         logging.info('%s server has UseLogonCredentials\
                                      set to 0x0 Details=%s, %s', server,
                                      'UseLogonCredential', 'CLOSE')
        else:
            result = True
            logging.info('%s server has not all required patches installed,\
                         Details=%s, %s', server,
                         ",".join(security_patches), 'OPEN')
    return result
