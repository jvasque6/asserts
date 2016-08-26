#!/bin/bash -x

source conf.sh

sudo docker build -t fluidsignal/$SERVICE container
