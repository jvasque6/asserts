#!/bin/bash -x

# shellcheck disable=SC1091
source conf.sh

sudo docker ps
sudo docker kill "$SERVICE"
sudo docker rm "$SERVICE"
sudo docker ps
