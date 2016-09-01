#!/bin/bash -x

# shellcheck disable=SC1091
source conf.sh

 lftp -c "set ftp:passive-mode yes; open -u root,root123 $VULNERABLE_IP; ls -al"
 lftp -c "set ftp:passive-mode yes; open -u root,root123 $HARDENED_IP; ls -al"
 lftp -c "set ftp:passive-mode no; open -u root,root123 $VULNERABLE_IP; ls -al"
 lftp -c "set ftp:passive-mode no; open -u root,root123 $HARDENED_IP; ls -al"
