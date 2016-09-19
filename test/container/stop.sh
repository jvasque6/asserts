#!/bin/bash

# habilitar depuración
if [ -n "$VERBOSE" ]; then
  set -x
fi

# Salir inmediatamente si algun comando retorna diferente de cero.
set -e

# importar entorno
source $(git rev-parse --show-toplevel)/env.sh

# detener contenedor si esta prendido en ambiente diferente a CIRCLECI
if [ -z $(docker ps -q -f name="$SERVICE") ]; then
  echo "Contenedor ya esta apagado."	 
elif [ -n "$CIRCLECI" ]; then
  # este es un workaround debido a que en CIRCLECI no hay docker rm/kill
  echo "Contenedor prendido, pero en CIRCLECI, reutilizandolo."	 
  CONTAINER_ACTIVE="yes"
else
  echo "Contenedor prendido, y no en CIRCLECI, deteniendolo..."
  docker kill "$SERVICE"
  docker rm "$SERVICE"
fi

# eliminar red de contenedores si esta establecida
if [ -z $(docker network ls -q -f name="$NET_NAME") ]; then
  echo "Red ya eliminada..."
elif [ -n "$CONTAINER_ACTIVE" ]; then
  echo "Contenedores aun prendidos, mantener red prendida..."
else
  echo "Red configurada y sin contenedores activos, eliminandola..."
  docker network rm fluidasserts
fi

# eliminar claves de accesso a contenedor
rm -f ~/.ssh/config.facont
rm -f ~/.ssh/facont_id_rsa*
