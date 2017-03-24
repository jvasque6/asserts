#!/bin/bash

# habilitar depuración
if [ -n "$VERBOSE" ]; then
  set -x
fi

# Salir inmediatamente si algun comando retorna diferente de cero.
set -e

# importar entorno
#source $(git rev-parse --show-toplevel)/servers/integrates/vars/env.sh
source servers/integrates/vars/env.sh

# Mensaje de inicio
echo "---### Compilando contenedor."

# construir la imagen
docker build -t fluidsignal/fluidasserts-dev:ubuntu \
             containers/ubuntu