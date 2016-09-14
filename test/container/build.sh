#!/bin/bash

# Salir inmediatamente si algun comando retorna diferente de cero.
set -e

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
  IMAGE_PATH=$(dirname $1)/image
fi

docker build -t fluidsignal/"$SERVICE" "$IMAGE_PATH"
