#!/bin/bash

# Salir inmediatamente si algun comando retorna diferente de cero.
set -e

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

# Probando conexion SSH
ssh "$IP" "echo working"
ssh "$IP" -l nonpriv "echo working"

# probando conexion Ansible
#ansible "$IP" -a "echo working"
#ansible "$IP" -m shell -a "echo working"

# Probando modulo de root
#ansible container -m ping

# Probando credenciales no privilegiados y de root
#ansible container -m shell -a "id"
#ansible container -m shell -a "id" -b
