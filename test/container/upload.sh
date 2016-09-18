#!/bin/bash

# Salir inmediatamente si algun comando retorna diferente de cero.
set -e

# importar entorno
source $(git rev-parse --show-toplevel)/env.sh

# subirla al repositorio
docker push fluidsignal/fluidasserts:"$SERVICE"
