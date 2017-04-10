#!/bin/bash

# habilitar depuración
if [ -n "$VERBOSE" ]; then
  set -x
fi

# Salir inmediatamente si algun comando retorna diferente de cero.
set -e

# Mensaje de inicio
echo "---### Deteniendo contenedor."

# importar entorno
source $(git rev-parse --show-toplevel)/test/env.sh

# detener contenedor si esta encendido en ambiente diferente a CIRCLECI
if [ -z $(docker ps -q -f name="$SERVICE") ]; then
  echo "Contenedor ya apagado."
elif [ -n "$CIRCLECI" ]; then
  # este es un workaround debido a que en CIRCLECI no hay docker rm/kill
  echo "Contenedor a) encendido, pero b) en CIRCLECI, reutilizando."
  CONTAINER_ACTIVE="yes"
else
  echo "Contenedor a) encendido, y b) no en CIRCLECI, deteniendo."
  docker kill "$SERVICE"
  docker rm "$SERVICE"

  # eliminar claves de accesso a contenedor
  rm -f ~/.ssh/config.facont
  rm -f ~/.ssh/facont_id_rsa*
fi

# eliminar red de contenedores si esta establecida
if [ -z $(docker network ls -q -f name="$NET_NAME") ]; then
  echo "Red ya eliminada."
elif [ -n "$CONTAINER_ACTIVE" ]; then
  echo "Contenedores aun prendidos, mantener red encendida."
else
  echo "Red configurada y sin contenedores activos, eliminando red."
  docker network rm fluidasserts
fi
