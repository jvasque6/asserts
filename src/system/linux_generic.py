# -*- coding: utf-8 -*-
"""Linux OS module."""

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
def is_os_min_priv_disabled(server, username, password, ssh_config=None):
    """Check if umask or similar is secure in os_linux_generic."""
    result = True
    cmd = 'umask'
    out, _ = ssh_exec_command(server, username, password, cmd,
                              ssh_config)

    if out == '0027':
        show_close('{} server has secure default privileges'.
                   format(server), details='umask={}'.format(out))
        result = False
    else:
        show_open('{} server has too open default privileges'.
                  format(server), details='umask={}'.format(out))
        result = True
    return result


def is_os_sudo_disabled(server, username, password, ssh_config=None):
    """Check if there's sudo or similar installed in os_linux_generic."""
    result = True
    cmd = 'which sudo'
    out, _ = ssh_exec_command(server, username, password, cmd,
                              ssh_config)

    if out:
        show_close('{} server has sudo (or like) installed'.
                   format(server), details='{}'.format(out))
        result = False
    else:
        show_open('{} server has not sudo (or like) installed'.
                  format(server), details='{}'.format(out))
        result = True
    return result


@track
def is_os_compilers_installed(server, username, password,
                              ssh_config=None):
    """Check if there's any compiler installed in os_linux_generic."""
    result = True
    cmd = 'which cc gcc c++ g++ javac ld as nasm'
    out, _ = ssh_exec_command(server, username, password, cmd,
                              ssh_config)

    if not out:
        show_close('{} server has not compilers installed'.
                   format(server), details='{}'.format(out))
        result = False
    else:
        show_open('{} server has compilers installed'.format(server),
                  details='{}'.format(out))
        result = True
    return result


def is_os_antimalware_not_installed(server, username, password,
                                    ssh_config=None):
    """Check if there's any antimalware installed in os_linux_generic."""
    result = True
    cmd = 'which clamscan avgscan'
    out, _ = ssh_exec_command(server, username, password, cmd,
                              ssh_config)

    if out:
        show_close('{} server has an antivirus installed'.format(server),
                   details='{}'.format(out))
        result = False
    else:
        show_open('{} server has not an antivirus installed'.
                  format(server), details='{}'.format(out))
        result = True
    return result


@track
def is_os_remote_admin_enabled(server, username, password,
                               ssh_config=None):
    """Check if admins can remotely login in os_linux_generic."""
    result = True
    cmd = 'grep -i "^PermitRootLogin.*yes" /etc/ssh/sshd_config'
    out, _ = ssh_exec_command(server, username, password, cmd,
                              ssh_config)

    if not out:
        show_close('{} server has not remote admin login enabled'.
                   format(server), details='{}'.format(out))
        result = False
    else:
        show_open('{} server has remote admin login enabled'.
                  format(server), details='{}'.format(out))
        result = True
    return result


@track
def is_os_syncookies_disabled(server, username, password,
                              ssh_config=None):
    """Check if SynCookies or similar is enabled in os_linux_generic."""
    result = True
    cmd = 'sysctl -q -n net.ipv4.tcp_syncookies'
    out, _ = ssh_exec_command(server, username, password, cmd,
                              ssh_config)

    if not out:
        show_close('{} server has syncookies enabled'.
                   format(server), details='{}'.format(out))
        return False

    if int(out) == 1:
        show_close('{} server has syncookies enabled'.
                   format(server), details='{}'.format(out))
        result = False
    else:
        show_open('{} server has syncookies disabled'.
                  format(server), details='{}'.format(out))
        result = True
    return result
