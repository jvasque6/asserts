#!/bin/bash -x

# shellcheck disable=SC1091
source conf.sh

sudo docker ps
sudo docker kill "$SERVICE"-vulnerable
sudo docker rm "$SERVICE"-vulnerable
sudo docker kill "$SERVICE"-hardened
sudo docker rm "$SERVICE"-hardened
sudo docker ps
