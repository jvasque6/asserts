#!/bin/bash -x

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
		--name="$SERVICE"-vulnerable \
		--hostname="$SERVICE"-vulnerable \
		--env \
			FLAVOR=vulnerable \
		--net="$NET_NAME" \
		--ip="$VULNERABLE_IP" \
		--publish-all \
		fluidsignal/"$SERVICE"

docker run \
		--detach \
		--name="$SERVICE"-hardened \
		--hostname="$SERVICE"-hardened \
		--env \
			FLAVOR=hardened \
		--net="$NET_NAME" \
		--ip="$HARDENED_IP" \
		--publish-all \
		fluidsignal/"$SERVICE"
