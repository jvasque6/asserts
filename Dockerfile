FROM debian:stable-slim

WORKDIR /usr/src/app

RUN apt-get update -qq && \
    apt-get install -y python3 python3-dev python-dev libssl-dev libffi-dev scons python-virtualenv sed curl grep gawk lsb-release netcat-traditional && \
    apt-get install -y python-pip python3-pip python-setuptools python3-setuptools apt-transport-https ca-certificates tesseract-ocr && \
    pip install -U tox tox-pyenv flake8 pylint yamllint twine certifi ansible wheel colorama mandrill

RUN echo "deb [arch=amd64] https://download.docker.com/linux/debian stretch stable" > /etc/apt/sources.list.d/docker.list
RUN curl -fsSL https://download.docker.com/linux/$(. /etc/os-release; echo "$ID")/gpg | apt-key add -

RUN apt-get update -qq && apt-get install -y docker-ce
