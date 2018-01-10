# -*- coding: utf-8 -*-
"""Windows Server OS module."""

# standard imports
import logging
import re

# 3rd party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.helper.winrm_helper import winrm_exec_command
from fluidasserts.utils.decorators import track

LOGGER = logging.getLogger('FLUIDAsserts')


# pylint: disable=W1401
# pylint: disable=W1402
@track
def is_os_compilers_installed(server, username, password):
    """Check if there's any compiler installed in Windows Server."""
    common_compilers = ['Visual', 'Python', 'Mingw', 'CygWin']
    cmd = b'reg query \
           "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall" /s'

    installed_software = winrm_exec_command(server,
                                            username,
                                            password,
                                            cmd)

    installed_compilers = 0

    for compiler in common_compilers:
        if re.search(compiler, installed_software,
                     re.IGNORECASE) is not None:
            installed_compilers = installed_compilers + 1

    result = True
    if installed_compilers > 0:
        LOGGER.info('%s: %s server has compilers installed,\
Details=%s', show_open(), server, installed_software)
        result = True
    else:
        LOGGER.info('%s: %s server has not compilers installed,\
Details=%s', show_close(), server, installed_software)
        result = False
    return result


@track
def is_os_antimalware_not_installed(server, username, password):
    """Check if there's any antimalware installed in Windows Server."""
    common_av = ['Symantec', 'Norton', 'AVG', 'Kaspersky', 'TrendMicro',
                 'Panda', 'Sophos', 'McAfee', 'Eset']
    cmd = b'reg query \
           "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall" /s'
    installed_software = winrm_exec_command(server,
                                            username,
                                            password,
                                            cmd)

    installed_av = 0

    for antivirus in common_av:
        if re.search(antivirus, installed_software,
                     re.IGNORECASE) is not None:
            installed_av = installed_av + 1

    result = True
    if installed_av > 0:
        LOGGER.info('%s: %s server has an antivirus installed, \
Details=%s', show_close(), server, installed_software)
        result = False
    else:
        LOGGER.info('%s: %s server has not an antivirus installed, \
Details=%s', show_open(), server, installed_software)
        result = True
    return result


@track
def is_os_syncookies_disabled(server):
    """Check if SynCookies or similar is enabled in Windows Server."""
    # On Windows, SYN Cookies are enabled by default and there's no
    # way to disable it.
    LOGGER.info('%s: %s server has SYN Cookies enabled.', show_close(),
                server)
    return False


@track
def is_protected_users_disabled(server, username, password):
    """Check if protected users is enabled on system.

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

    for patch in security_patches:
        if re.search(patch, installed_software,
                     re.IGNORECASE) is not None:
            installed_patches = installed_patches + 1

    result = True
    if installed_patches == len(security_patches):
        LOGGER.info('%s: %s server has all required patches installed, \
Details=%s', show_close(), server, ",".join(security_patches))
        result = False
    else:
        cmd = b'reg query \
"HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" \
/v UseLogonCredential'

        has_logon_credentials = winrm_exec_command(server,
                                                   username,
                                                   password,
                                                   cmd)
        if re.search('UseLogonCredential.*0x0',
                     has_logon_credentials,
                     re.IGNORECASE) is not None:
            result = False
            LOGGER.info('%s: %s server has UseLogonCredentials\
set to 0x0 Details=%s', show_close(), server, 'UseLogonCredential')
        else:
            result = True
            LOGGER.info('%s: %s server has not all required patches \
installed, Details=%s', show_open(), server, ",".join(security_patches))
    return result
