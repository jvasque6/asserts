# -*- coding: utf-8 -*-

"""This module allows to check generic MySQL OS (Linux) vulnerabilities."""

# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.helper.ssh_helper import ssh_exec_command, ConnError
from fluidasserts.utils.decorators import track, level


@level('high')
@track
def daemon_high_privileged(server: str, username: str, password: str,
                           ssh_config: str = None) -> bool:
    """Check if current MySQL installation uses non-privileged user."""
    cmds = [
        ('ps -o user= -p $(pgrep mysql)', 'mysql'),
        ('grep -o ^mysql /etc/passwd', 'mysql'),
        ('stat -c %U /var/lib/mysql', 'mysql')
    ]
    for cmd in cmds:
        try:
            out, _ = ssh_exec_command(server, username, password, cmd[0],
                                      ssh_config)
        except ConnError as exc:
            show_unknown('Could not connect',
                         details=dict(server=server, username=username,
                                      error=str(exc)))
            return False
        else:
            if out.decode() == cmd[1]:
                show_close('MySQL server is running with a \
non-privileged account',
                           details=dict(server=server,
                                        process_owner=out.decode()))
                return False
    show_open('MySQL server is not running with a non-privileged account',
              details=dict(server=server, process_owner=out.decode()))
    return True


@level('low')
@track
def history_enabled(server: str, username: str, password: str,
                    ssh_config: str = None) -> bool:
    """Check for .mysql_history files."""
    cmd = r'c=0; for i in $(find /home -name .mysql_history); \
do size=$(stat -c %b $i); c=$(($c+$size)); done; echo $c'
    try:
        out, _ = ssh_exec_command(server, username, password, cmd,
                                  ssh_config)
    except ConnError as exc:
        show_unknown('Could not connect',
                     details=dict(server=server, username=username,
                                  error=str(exc)))
        return False
    if out.decode() == '0' or out.decode() == '':
        show_close('MySQL history files are empty',
                   details=dict(server=server, size=out.decode()))
        return False
    show_open('MySQL history files are not empty',
              details=dict(server=server, size=out.decode()))
    return True


@level('high')
@track
def pwd_on_env(server: str, username: str, password: str,
               ssh_config: str = None) -> bool:
    """Check for MYSQL_PWD env var."""
    cmd = r'grep -h MYSQL_PWD /proc/*/environ \
/home/*/.{bashrc,profile,bash_profile}'
    try:
        out, _ = ssh_exec_command(server, username, password, cmd,
                                  ssh_config)
    except ConnError as exc:
        show_unknown('Could not connect',
                     details=dict(server=server, username=username,
                                  error=str(exc)))
        return False
    if out.decode() == '':
        show_close('MYSQL_PWD not on environment',
                   details=dict(server=server))
        return False
    show_open('MYSQL_PWD found on environment',
              details=dict(server=server, values=out.decode()))
    return True


@level('medium')
@track
def has_insecure_shell(server: str, username: str, password: str,
                       ssh_config: str = None) -> bool:
    """Check for mysql user with interactive shell."""
    cmd = r'getent passwd mysql | cut -d: -f7 | grep -e nologin -e false'
    try:
        out, _ = ssh_exec_command(server, username, password, cmd,
                                  ssh_config)
    except ConnError as exc:
        show_unknown('Could not connect',
                     details=dict(server=server, username=username,
                                  error=str(exc)))
        return False
    if out.decode() != '':
        show_close('"mysql" user uses a non-interactive shell',
                   details=dict(server=server, shell=out.decode()))
        return False
    show_open('"mysql" user uses an interactive shell',
              details=dict(server=server))
    return True
