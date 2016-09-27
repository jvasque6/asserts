#!/bin/bash

# habilitar depuración
if [ -n "$VERBOSE" ]; then
  set -x
fi

# Salir inmediatamente si algun comando retorna diferente de cero.
set -e

# importar entorno
source $(git rev-parse --show-toplevel)/env.sh

# construir la imagen
docker build -t fluidsignal/fluidasserts:"$SERVICE" \
             "$PROJECT_DIR"/test/container
