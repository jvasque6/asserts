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
from fluidasserts.utils.decorators import track


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
