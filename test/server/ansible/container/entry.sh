#!/bin/sh

echo "FLUIDAsserts - Ansible Base server"

exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
