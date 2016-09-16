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

docker network create \
		--subnet="$NET_IP" \
		"$NET_NAME"

# En cada inicio se configura la conexión SSH correspondiente
# Este archivo de configuración de SSH tambien esta parametrizado
# en setup/config sección ssh, parametro ssh_args
export PROJECT_PATH="${ANSIBLE_CONFIG%/*/*/*}"
cp "$PROJECT_PATH"/test/setup/ssh_config ~/.ssh/config.facont
echo -e "y\n" | ssh-keygen -b 2048 -t rsa -f ~/.ssh/facont_id_rsa -q -N ""
#test -f ~/.ssh/facont_id_rsa || ssh-keygen -q -N "" -t rsa -b 2048 -f ~/.ssh/facont_id_rsa

docker run \
		--detach \
		--name="$SERVICE" \
		--hostname="$SERVICE" \
		--net "$NET_NAME" \
		--ip "$IP" \
		--publish-all \
		--volume=/tmp:/host/tmp \
		-e SSH_KEY="$(cat ~/.ssh/facont_id_rsa.pub)" \
		fluidsignal/"$SERVICE"
