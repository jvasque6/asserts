#!/bin/bash -x

# shellcheck disable=SC1091
source conf.sh

sudo docker network create \
		--subnet="$NET_IP" \
		"$NET_NAME"

sudo docker run \
		--detach \
		--name="$SERVICE" \
		--hostname="$SERVICE" \
		--net "$NET_NAME" \
		--ip "$IP" \
		--publish-all \
		--volume=/tmp:/host/tmp \
		fluidsignal/"$SERVICE"
