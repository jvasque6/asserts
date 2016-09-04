#!/bin/bash

if [ -z "${1+x}" ]; then
  echo "Archivo de configuración no especificado."
  echo "Uso: $0 conf.sh"
  exit -1
elif [ ! -f "$1" ]; then
  echo "Archivo de configuración $1 no existe."
  echo "Uso: $0 conf.sh"
  exit -2
else
  echo "Cargando archivo de configuración $1"
  source "$1"
fi

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
