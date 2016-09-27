#!/bin/sh

echo "FLUIDAsserts - SSH Mock server - FLAVOR=$FLAVOR"

exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config."$FLAVOR"
