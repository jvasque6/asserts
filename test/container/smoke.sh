#!/bin/bash

# habilitar depuración
if [ -n "$VERBOSE" ]; then
  set -x
fi

# Salir inmediatamente si algun comando retorna diferente de cero.
set -e

# importar entorno (SSH_AUTH_SOCK reseteado)
source $(git rev-parse --show-toplevel)/env.sh

# Probando conexion SSH
ssh ${VERBOSE:+-vvv} -F ~/.ssh/config.facont "$IP" -l nonpriv \
	echo "SSH connection as nonpriv to container is working"
ssh ${VERBOSE:+-vvv} -F ~/.ssh/config.facont "$IP" -l root \
	echo "SSH connection as root to container is working"
