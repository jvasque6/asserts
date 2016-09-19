#!/bin/bash

# habilitar depuración
if [ -n "$VERBOSE" ]; then
  set -x
fi

# salir al primer error
set -e

# importar entorno (ANSIBLE_*)
source $(git rev-parse --show-toplevel)/env.sh

# Probando modulo de root
ansible container ${VERBOSE:+-vvv} -m ping 

# Probando credenciales no privilegiados y de root
ansible container ${VERBOSE:+-vvv} -m shell -a "id"
ansible container ${VERBOSE:+-vvv} -m shell -a "id" -b
