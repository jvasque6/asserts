#!/bin/bash -x

source conf.sh

ssh $IP "echo working"
ansible $IP -a "echo working"
ansible $IP -m shell -a "echo working"
