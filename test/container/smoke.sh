#!/bin/bash

# Salir inmediatamente si algun comando retorna diferente de cero.
set -e

# habilitar depuración
set -x

# importar entorno (SSH_AUTH_SOCK reseteado)
source $(git rev-parse --show-toplevel)/env.sh

# Probando conexion SSH
ssh -vvv -F ~/.ssh/config.facont "$IP" -l nonpriv \
	echo "SSH connection as nonpriv to container is working"
ssh -vvv -F ~/.ssh/config.facont "$IP" -l root \
	echo "SSH connection as root to container is working"
