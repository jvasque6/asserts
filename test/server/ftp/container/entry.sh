#!/bin/sh

echo "FLUIDAsserts - FTP Mock server - FLAVOR=$FLAVOR"

exec /usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf.$FLAVOR
