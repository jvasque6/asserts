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

docker network create \
		--subnet="$NET_IP" \
		"$NET_NAME"

docker run \
		--detach \
		--name="$SERVICE" \
		--hostname="$SERVICE" \
		--net "$NET_NAME" \
		--ip "$IP" \
		--publish-all \
		--volume=/tmp:/host/tmp \
		-e SSH_KEY="$(cat ~/.ssh/id_rsa.pub)" \
		fluidsignal/"$SERVICE"
