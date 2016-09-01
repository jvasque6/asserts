#!/bin/bash -x

# shellcheck disable=SC1091
source conf.sh

sudo docker build -t fluidsignal/"$SERVICE" container
