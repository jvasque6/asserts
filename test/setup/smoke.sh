#!/bin/bash

# depuración
set -x

# salir al primer error
set -e

export ANSIBLE_HOSTS=./hosts
export ANSIBLE_CONFIG=./config

# probando conexion Ansible
ansible container -a "echo working"
ansible container -m shell -a "echo working"

# Probando modulo de root
ansible container -m ping 

# Probando credenciales no privilegiados y de root
ansible container -m shell -a "id"
ansible container -m shell -a "id" -b
