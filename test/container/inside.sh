#!/bin/bash

# habilitar depuración
if [ -n "$VERBOSE" ]; then
  set -x
fi

# importar entorno
source $(git rev-parse --show-toplevel)/test/env.sh

docker network create \
		--subnet="$NET_IP" \
		"$NET_NAME"

# crear claves de acceso al contenedor
cp "$PROJECT_DIR"/test/setup/ssh_config ~/.ssh/config.facont
echo -e "y\n" | ssh-keygen -b 2048 -t rsa -f ~/.ssh/facont_id_rsa -q -N ""

docker run \
		--tty \
		--interactive \
		--name="$SERVICE"-inside \
		--hostname="$SERVICE"-inside \
		--net "$NET_NAME" \
		--ip "$IP" \
		--publish-all \
                --entrypoint=/bin/bash \
		--volume=/tmp:/host/tmp \
		--volume=/var/run/docker.sock:/var/run/docker.sock \
		-e SSH_KEY="$(cat ~/.ssh/facont_id_rsa.pub)" \
		fluidsignal/fluidasserts:"$SERVICE"

docker rm "$SERVICE"-inside

# eliminar red de contenedores
docker network rm fluidasserts

# eliminar claves de accesso a contenedor
rm -f ~/.ssh/config.facont
rm -f ~/.ssh/facont_id_rsa*
