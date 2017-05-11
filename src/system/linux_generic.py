# -*- coding: utf-8 -*-
"""Modulo OS os_linux_generic."""

# standard imports
import logging

# 3rd party imports
from fluidasserts import show_close
from fluidasserts import show_open

# local imports
from fluidasserts.helper.ssh_helper import ssh_exec_command

logger = logging.getLogger('FLUIDAsserts')


def is_os_min_priv_disabled(server, username, password, ssh_config=None):
    """Check if umask or similar is secure in os_linux_generic."""
    result = True
    cmd = 'umask'
    out, _ = ssh_exec_command(server, username, password, cmd,
                              ssh_config)

    if out is '0027':
        logger.info('%s server has secure default privileges,\
Details=umask %s, %s', server, out, show_close())
        result = False
    else:
        logger.info('%s server has too open default privileges,\
Details=umask %s, %s', server, out, show_open())
        result = True
    return result


def is_os_sudo_disabled(server, username, password, ssh_config=None):
    """Check if there's sudo or similar installed in os_linux_generic."""
    result = True
    cmd = 'which sudo'
    out, _ = ssh_exec_command(server, username, password, cmd,
                              ssh_config)

    if len(out) > 0:
        logger.info('%s server has sudo (or like) installed,\
Details=%s, %s', server, out, show_close())
        result = False
    else:
        logger.info('%s server has not sudo (or like) installed,\
Details=%s, %s', server, out, show_open())
        result = True
    return result


def is_os_compilers_installed(server, username, password,
                              ssh_config=None):
    """Check if there's any compiler installed in os_linux_generic."""
    result = True
    cmd = 'which cc gcc c++ g++ javac ld as nasm'
    out, _ = ssh_exec_command(server, username, password, cmd,
                              ssh_config)

    if len(out) == 0:
        logger.info('%s server has not compilers installed,\
Details=%s, %s', server, out, show_close())
        result = False
    else:
        logger.info('%s server has compilers installed,\
Details=%s, %s', server, out, show_open())
        result = True
    return result


def is_os_antimalware_not_installed(server, username, password,
                                    ssh_config=None):
    """Check if there's any antimalware installed in os_linux_generic."""
    result = True
    cmd = 'which clamscan avgscan'
    out, _ = ssh_exec_command(server, username, password, cmd,
                              ssh_config)

    if len(out) > 0:
        logger.info('%s server has an antivirus installed,\
Details=%s, %s', server, out, show_close())
        result = False
    else:
        logger.info('%s server has not an antivirus installed,\
Details=%s, %s', server, out, show_open())
        result = True
    return result


def is_os_remote_admin_enabled(server, username, password,
                               ssh_config=None):
    """Check if admins can remotely login in os_linux_generic."""
    result = True
    cmd = 'grep -i "^PermitRootLogin.*yes" /etc/ssh/sshd_config'
    out, _ = ssh_exec_command(server, username, password, cmd,
                              ssh_config)

    if len(out) == 0:
        logger.info('%s server has not remote admin login enabled,\
Details=%s, %s', server, out, show_close())
        result = False
    else:
        logger.info('%s server has remote admin login enabled,\
Details=%s, %s', server, out, show_open())
        result = True
    return result


def is_os_syncookies_disabled(server, username, password,
                              ssh_config=None):
    """Check if SynCookies or similar is enabled in os_linux_generic."""
    result = True
    cmd = 'sysctl -q -n net.ipv4.tcp_syncookies'
    out, _ = ssh_exec_command(server, username, password, cmd,
                              ssh_config)

    if len(out) == 0:
        logger.info('%s server has syncookies enabled,\
Details=%s, %s', server, out, show_close())
        return False

    if int(out) == 1:
        logger.info('%s server has syncookies enabled,\
Details=%s, %s', server, out, show_close())
        result = False
    else:
        logger.info('%s server has syncookies disabled,\
Details=%s, %s', server, out, show_open())
        result = True
    return result
