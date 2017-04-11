# Imagen base de linux Debian
FROM debian:jessie

# Dudas sobre la imagen en cuestion
MAINTAINER FLUID Engineering Team <engineering@fluid.la>

ENV DEBIAN_FRONTEND noninteractive      # instalación no interactiva
ENV USER root

# Instala SSH, Python y SUDO para administracion por Ansible
RUN apt-get update && apt-get -y upgrade && apt-get install -y \
	sudo \
	python \
	apt-transport-https \
	ca-certificates \
	curl \
	software-properties-common \
	bash \
	python-pip \
	python3-pip \
	scons \
	libssl-dev \
	libffi-dev \
	python3-dev \
	python-dev \
	g++ \
	gcc
RUN echo "deb https://download.docker.com/linux/ubuntu trusty stable" >> /etc/apt/sources.list.d/docker.list
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
RUN apt-get update && apt-get -y install docker-ce
RUN pip install -U --force pip setuptools && pip3 install -U --force pip setuptools
RUN apt-get -y purge python-setuptools python3-setuptools
RUN pip install -U --force pip setuptools && pip3 install -U --force pip setuptools
RUN pip install -U tox ansible && pip3 install -U tox ansible
