#!/bin/bash

# habilitar depuración
set -x

# importar entorno
source $(git rev-parse --show-toplevel)/env.sh

# crear red de contenedores
docker network create \
		--subnet="$NET_IP" \
		"$NET_NAME"

# Crear dinamicamente claves de acceso al contenedor
# La ruta de configuración SSH tambien esta parametrizado en test/setup/hosts
cp "$PROJECT_DIR"/test/setup/ssh_config ~/.ssh/config.facont
echo -e "y\n" | ssh-keygen -b 2048 -t rsa -f ~/.ssh/facont_id_rsa -q -N ""

# iniciar contenedor
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
echo "Waiting 5 seconds until container start"
sleep 5 
