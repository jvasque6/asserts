#!/bin/bash

# habilitar depuración
set -x

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

docker ps
docker kill "$SERVICE"
docker rm "$SERVICE"
docker ps

docker network rm fluidasserts
docker network ls

rm ~/.ssh/facont_id_rsa* ~/.ssh/config.facont
