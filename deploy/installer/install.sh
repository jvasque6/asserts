#!/bin/bash

check_root()
{
	if [[ $(id -u) != 0 ]]; then
		echo "This script must be run as root"
		exit 1
	fi
}

check_root
apt-get update
apt-get install -y python3 python3-pip

python3 -m pip install -U --no-index --find-links=$PWD/packages pip setuptools
python3 -m pip install -U --no-index --find-links=$PWD/packages fluidasserts
