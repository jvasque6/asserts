#!/bin/bash -x

# shellcheck disable=SC1091
source conf.sh

sudo docker network create \
		--subnet="$NET_IP" \
		"$NET_NAME"

sudo docker run \
		--tty \
		--interactive \
		--volume=/tmp:/backup \
		--name="$SERVICE"-testing \
		--hostname="$SERVICE"-testing \
		--net "$NET_NAME" \
		--ip "$TEST_IP" \
		--publish-all \
                --entrypoint=/bin/sh \
		fluidsignal/"$SERVICE"

sudo docker rm "$SERVICE"-testing
