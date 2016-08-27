#!/bin/sh

echo "FLUIDAsserts - LDAP Mock server - FLAVOR=$FLAVOR"

#exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config.$FLAVOR
#exec /usr/sbin/slapd -d 256 -u ldap -g ldap -F /etc/openldap/slapd.d
exec /usr/sbin/slapd -d 256
