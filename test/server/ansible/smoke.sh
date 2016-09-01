#!/bin/bash -x

# shellcheck disable=SC1091
source conf.sh

ssh "$IP" "echo working"
ansible "$IP" -a "echo working"
ansible "$IP" -m shell -a "echo working"
