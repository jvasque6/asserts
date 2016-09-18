#!/bin/bash

# habilitar depuración
set -x

# importar entorno
source $(git rev-parse --show-toplevel)/env.sh

# detener contenedor
docker kill "$SERVICE"
docker rm "$SERVICE"

# eliminar red de contenedores
docker network rm fluidasserts

# eliminar claves de accesso a contenedor
rm -f ~/.ssh/config.facont
rm -f ~/.ssh/facont_id_rsa*
