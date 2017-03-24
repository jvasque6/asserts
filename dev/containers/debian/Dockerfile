# Imagen base de linux Debian
FROM debian:jessie

# Dudas sobre la imagen en cuestion
MAINTAINER FLUID Engineering Team <engineering@fluid.la>

ENV DEBIAN_FRONTEND noninteractive      # instalación no interactiva
ENV USER root

# Instala SSH, Python y SUDO para administracion por Ansible
RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get install -y sudo python apt-transport-https ca-certificates curl software-properties-common bash
RUN echo "deb https://download.docker.com/linux/debian jessie stable" >> /etc/apt/sources.list.d/docker.list
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | apt-key add -
RUN apt-get update
RUN apt-get -y install python-pip python3-pip docker-ce
RUN apt-get -y install scons libssl-dev libffi-dev python3-dev python-dev g++ gcc
RUN pip install -U pip setuptools
RUN pip3 install -U pip setuptools
RUN apt-get -y purge python-setuptools python3-setuptools
RUN pip install -U tox ansible
RUN pip3 install -U tox ansible

