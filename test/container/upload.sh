#!/bin/bash

# habilitar depuración
if [ -n "$VERBOSE" ]; then
  set -x
fi

# Salir inmediatamente si algun comando retorna diferente de cero.
set -e

# Mensaje de inicio
echo "---### Actualizando contenedor en la nube."

# importar entorno
source $(git rev-parse --show-toplevel)/env.sh

# subirla al repositorio
docker push fluidsignal/fluidasserts:"$SERVICE"
