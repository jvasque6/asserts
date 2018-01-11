FROM debian:stable-slim

WORKDIR /usr/src/asserts

RUN apt-get update -qq && \
    apt-get install -qqy --no-install-recommends \
        curl \
        apt-transport-https \
        ca-certificates \
        gpg && \
    dpkg --clear-avail && \
    apt-get clean

RUN echo "deb [arch=amd64] https://download.docker.com/linux/debian stretch stable" > /etc/apt/sources.list.d/docker.list

RUN curl -fsSL https://download.docker.com/linux/$(. /etc/os-release; echo "$ID")/gpg | apt-key add -

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-dev \
        python-dev \
        libssl-dev \
        libffi-dev \
        scons \
        python-virtualenv \
        sed \
        grep \
        gawk \
        lsb-release \
        netcat-traditional \
        python-pip \
        python3-pip \
        python-setuptools \
        python3-setuptools \
        tesseract-ocr \
        ruby \
        ruby2.3-dev \
        libffi-dev \
        pkg-config \
        gcc \
        libc6-dev \
        make \
        docker-ce \
        git && \
    pip install -U pip \
        setuptools  \
        wheel && \
    pip install -U \
        tox \
        tox-pyenv \
        pylint \
        flake8 \
        yamllint \
        pyflakes \
	pycodestyle \
        pydocstyle \
        pep257 \
        twine \
	mandrill \
        certifi && \
    gem install overcommit && \
    dpkg --clear-avail && \
    apt-get clean
