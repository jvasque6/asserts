#!/bin/bash

# habilitar depuración
if [ -n "$VERBOSE" ]; then
  set -x
fi

# Salir inmediatamente si algun comando retorna diferente de cero.
set -e

# La clave publica para conectarse es pasada por parametros
if [ -z "${SSH_KEY}" ]; then
  echo "Indique su clave publica en la variable de entorno SSH_KEY"
  echo "Ejemplo: $ docker run ... -e SSH_KEY=\"$(cat ~/.ssh/id_rsa.pub)\" ... "
  exit -1
fi

# Almancenando claves publicas y definiendo permisos requeridos
  echo "Adicionando clave publica SSH a /root"
  mkdir -p ~/.ssh
  chmod go-rwx ~/.ssh
  echo "$SSH_KEY" > ~/.ssh/authorized_keys
  chmod go-rw ~/.ssh/authorized_keys

# Imprimiendo banner de inicio del server
echo "FLUIDAsserts container"

# Configurando conexión SSH para Ansible (en CI falla con PAM)
sed -i "s/UsePAM yes/UsePAM no/" /etc/ssh/sshd_config

# Iniciando servidor ssh
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config

# Establece ambiente para desarrollo
apt-get install -y apt-transport-https ca-certificates curl software-properties-common
echo "deb https://download.docker.com/linux/debian jessie stable" >> /etc/apt/sources.list.d/docker.list
curl -fsSL https://download.docker.com/linux/debian/gpg | apt-key add -
apt-get update
apt-get -y install python-pip python3-pip docker-ce
apt-get -y install scons libssl-dev libffi-dev python3-dev python-dev g++ gcc
pip install -U pip setuptools
apt-get -y purge python-setuptools python3-setuptools
/usr/local/bin/pip install -U pip setuptools
/usr/local/bin/pip3 install -U pip setuptools
/usr/local/bin/pip install -U tox ansible
/usr/local/bin/pip3 install -U tox ansible

# Basado en: https://hub.docker.com/r/krlmlr/debian-ssh/
