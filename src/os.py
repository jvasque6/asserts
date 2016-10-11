# -*- coding: utf-8 -*-
"""
Modulo OS general
"""

# standard imports
import logging

# 3rd party imports
# None

# local imports
from fluidasserts import os_linux_debian
from fluidasserts import os_linux_generic
from fluidasserts import os_linux_gentoo
from fluidasserts import os_linux_redhat
from fluidasserts import os_linux_slack
from fluidasserts import os_unix_generic
from fluidasserts import os_windows_vista_plus
from fluidasserts import os_windows_server_2008_plus

def is_os_min_priv_enabled(server, os_type):
    """
    Checks if umask or similar is secure
    """
    if os_type is 'LINUX_DEBIAN':
        os_linux_debian.is_os_min_priv_enabled(server)
    elif os_type is 'LINUX_GENERIC':
        os_linux_generic.is_os_min_priv_enabled(server)
    elif os_type is 'LINUX_GENTOO':
        os_linux_gentoo.is_os_min_priv_enabled(server)
    elif os_type is 'LINUX_REDHAT':
        os_linux_redhat.is_os_min_priv_enabled(server)
    elif os_type is 'LINUX_SLACK':
        os_linux_slack.is_os_min_priv_enabled(server)
    elif os_type is 'UNIX_GENERIC':
        os_unix_generic.is_os_min_priv_enabled(server)
    elif os_type is 'WINDOWS_VISTA_PLUS':
        os_windows_vista_plus.is_os_min_priv_enabled(server)
    elif os_type is 'WINDOWS_SERVER_2008_PLUS':
        os_windows_server_2008_plus.is_os_min_priv_enabled(server)


def is_os_sudo_enabled(server, os_type):
    """
    Checks if there's sudo or similar installed
    """
    if os_type is 'LINUX_DEBIAN':
        os_linux_debian.is_os_sudo_enabled(server)
    elif os_type is 'LINUX_GENERIC':
        os_linux_generic.is_os_sudo_enabled(server)
    elif os_type is 'LINUX_GENTOO':
        os_linux_gentoo.is_os_sudo_enabled(server)
    elif os_type is 'LINUX_REDHAT':
        os_linux_redhat.is_os_sudo_enabled(server)
    elif os_type is 'LINUX_SLACK':
        os_linux_slack.is_os_sudo_enabled(server)
    elif os_type is 'UNIX_GENERIC':
        os_unix_generic.is_os_sudo_enabled(server)
    elif os_type is 'WINDOWS_VISTA_PLUS':
        os_windows_vista_plus.is_os_sudo_enabled(server)
    elif os_type is 'WINDOWS_SERVER_2008_PLUS':
        os_windows_server_2008_plus.is_os_sudo_enabled(server)


def is_os_compilers_installed(server, os_type):
    """
    Checks if there's any compiler installed
    """
    if os_type is 'LINUX_DEBIAN':
        os_linux_debian.is_os_compilers_installed(server)
    elif os_type is 'LINUX_GENERIC':
        os_linux_generic.is_os_compilers_installed(server)
    elif os_type is 'LINUX_GENTOO':
        os_linux_gentoo.is_os_compilers_installed(server)
    elif os_type is 'LINUX_REDHAT':
        os_linux_redhat.is_os_compilers_installed(server)
    elif os_type is 'LINUX_SLACK':
        os_linux_slack.is_os_compilers_installed(server)
    elif os_type is 'UNIX_GENERIC':
        os_unix_generic.is_os_compilers_installed(server)
    elif os_type is 'WINDOWS_VISTA_PLUS':
        os_windows_vista_plus.is_os_compilers_installed(server)
    elif os_type is 'WINDOWS_SERVER_2008_PLUS':
        os_windows_server_2008_plus.is_os_compilers_installed(server)


def is_os_antimalware_installed(server, os_type):
    """
    Checks if there's any antimalware installed
    """
    if os_type is 'LINUX_DEBIAN':
        os_linux_debian.is_os_antimalware_installed(server)
    elif os_type is 'LINUX_GENERIC':
        os_linux_generic.is_os_antimalware_installed(server)
    elif os_type is 'LINUX_GENTOO':
        os_linux_gentoo.is_os_antimalware_installed(server)
    elif os_type is 'LINUX_REDHAT':
        os_linux_redhat.is_os_antimalware_installed(server)
    elif os_type is 'LINUX_SLACK':
        os_linux_slack.is_os_antimalware_installed(server)
    elif os_type is 'UNIX_GENERIC':
        os_unix_generic.is_os_antimalware_installed(server)
    elif os_type is 'WINDOWS_VISTA_PLUS':
        os_windows_vista_plus.is_os_antimalware_installed(server)
    elif os_type is 'WINDOWS_SERVER_2008_PLUS':
        os_windows_server_2008_plus.is_os_antimalware_installed(server)


def is_os_remote_admin_enabled(server, os_type):
    """
    Checks if admins can remotely login
    """
    if os_type is 'LINUX_DEBIAN':
        os_linux_debian.is_os_remote_admin_enabled(server)
    elif os_type is 'LINUX_GENERIC':
        os_linux_generic.is_os_remote_admin_enabled(server)
    elif os_type is 'LINUX_GENTOO':
        os_linux_gentoo.is_os_remote_admin_enabled(server)
    elif os_type is 'LINUX_REDHAT':
        os_linux_redhat.is_os_remote_admin_enabled(server)
    elif os_type is 'LINUX_SLACK':
        os_linux_slack.is_os_remote_admin_enabled(server)
    elif os_type is 'UNIX_GENERIC':
        os_unix_generic.is_os_remote_admin_enabled(server)
    elif os_type is 'WINDOWS_VISTA_PLUS':
        os_windows_vista_plus.is_os_remote_admin_enabled(server)
    elif os_type is 'WINDOWS_SERVER_2008_PLUS':
        os_windows_server_2008_plus.is_os_remote_admin_enabled(server)


def is_os_syncookies_enabled(server, os_type):
    """
    Checks if SynCookies or similar is enabled
    """
    if os_type is 'LINUX_DEBIAN':
        os_linux_debian.is_os_syncookies_enabled(server)
    elif os_type is 'LINUX_GENERIC':
        os_linux_generic.is_os_syncookies_enabled(server)
    elif os_type is 'LINUX_GENTOO':
        os_linux_gentoo.is_os_syncookies_enabled(server)
    elif os_type is 'LINUX_REDHAT':
        os_linux_redhat.is_os_syncookies_enabled(server)
    elif os_type is 'LINUX_SLACK':
        os_linux_slack.is_os_syncookies_enabled(server)
    elif os_type is 'UNIX_GENERIC':
        os_unix_generic.is_os_syncookies_enabled(server)
    elif os_type is 'WINDOWS_VISTA_PLUS':
        os_windows_vista_plus.is_os_syncookies_enabled(server)
    elif os_type is 'WINDOWS_SERVER_2008_PLUS':
        os_windows_server_2008_plus.is_os_syncookies_enabled(server)
