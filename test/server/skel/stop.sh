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

sudo docker ps
sudo docker kill "$SERVICE"-vulnerable
sudo docker rm "$SERVICE"-vulnerable
sudo docker kill "$SERVICE"-hardened
sudo docker rm "$SERVICE"-hardened
sudo docker ps
