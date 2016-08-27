#!/bin/bash -x

source conf.sh

sudo docker ps
sudo docker kill $SERVICE
sudo docker rm $SERVICE
sudo docker ps
