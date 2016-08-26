#!/bin/bash -x

source conf.sh

sudo docker network create \
		--subnet=$NET_IP \
		$NET_NAME

sudo docker run \
		--tty \
		--interactive \
		--name=$SERVICE \
		--hostname=$SERVICE \
		--net $NET_NAME \
		--ip $IP \
		--publish-all \
                --entrypoint=/bin/sh \
		--volume=/tmp:/host/tmp \
		fluidsignal/$SERVICE

sudo docker rm $SERVICE
