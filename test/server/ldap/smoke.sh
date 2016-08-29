#!/bin/bash -x

# shellcheck disable=SC1091
source conf.sh

ldapsearch -D "cn=Manager,dc=my-domain,dc=com" -w secret -p 389 -h "$VULNERABLE_IP" -b "dc=my-domain,dc=com" -s sub "(objectclass=*)"
ldapsearch -D "cn=Manager,dc=my-domain,dc=com" -w secret -p 389 -h "$HARDENED_IP" -b "dc=my-domain,dc=com" -s sub "(objectclass=*)"
