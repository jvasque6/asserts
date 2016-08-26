#!/bin/bash -x

# todo hoy solo funciona si se llama ./start.sh
# si se invoca desde CWD diferente a . no funciona
source conf.sh

sudo docker network create \
		--subnet=$NET_IP \
		$NET_NAME

sudo docker run \
		--detach \
		--name=$SERVICE-vulnerable \
		--hostname=$SERVICE-vulnerable \
		--env \
			FLAVOR=vulnerable \
		--net $NET_NAME \
		--ip $VULNERABLE_IP \
		--publish-all \
		fluidsignal/$SERVICE

sudo docker run \
		--detach \
		--name=$SERVICE-hardened \
		--hostname=$SERVICE-hardened \
		--env \
			FLAVOR=hardened \
		--net $NET_NAME \
		--ip $HARDENED_IP \
		--publish-all \
		fluidsignal/$SERVICE
