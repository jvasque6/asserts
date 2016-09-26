#!/bin/bash

# habilitar depuración
if [ -n "$VERBOSE" ]; then
  set -x
fi

# Salir inmediatamente si algun comando retorna diferente de cero.
set -e

# importar entorno
source $(git rev-parse --show-toplevel)/env.sh

# crear red de contenedores si no ha iniciado
if [ -z $(docker network ls -q -f name="$NET_NAME") ]; then
  echo "Red de contenedores no establecida, creando red..."
  docker network create \
		--subnet="$NET_IP" \
		"$NET_NAME"
else
  echo "Red ya configurada, reutilizando red..."
fi

# iniciar contenedor si no ha iniciado
if [ -z $(docker ps -q -f name="$SERVICE") ]; then
  echo "Contenedor no ha iniciado, iniciando contenedor..."	 

  # Crear dinamicamente claves de acceso al contenedor
  # La ruta de configuración SSH tambien esta parametrizado en test/setup/hosts
  cp "$PROJECT_DIR"/test/provision/ssh_config ~/.ssh/config.facont
  echo -e "y\n" | ssh-keygen -b 2048 -t rsa -f ~/.ssh/facont_id_rsa -q -N ""

  docker run \
		--detach \
		--name="$SERVICE" \
		--hostname="$SERVICE" \
		--net "$NET_NAME" \
		--ip "$IP" \
		--publish-all \
		--volume=/tmp:/host/tmp \
		-e SSH_KEY="$(cat ~/.ssh/facont_id_rsa.pub)" \
		fluidsignal/fluidasserts:"$SERVICE"

  # menos segundos genera fallos en la conexión
  echo "Esperando 5 segundos a que el contenedor inicie totalmente..."
  sleep 5 
else
  echo "Contenedor ya inicio, reutilizando contenedor..."
fi
