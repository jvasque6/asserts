# Imagen base del ultimo linux estable de Debian (jessie)
FROM debian:jessie

# Dudas sobre la imagen en cuestion
MAINTAINER FLUID Engineering Team <engineering@fluid.la>

ENV DEBIAN_FRONTEND noninteractive      # instalación no interactiva

# Instala SSH, Python y SUDO para administracion por Ansible
RUN apt-get update \
    && apt-get install -y \
               vim \
               sudo \
               python \
               openssh-server \
    && sed -i "s/UsePrivilegeSeparation yes/UsePrivilegeSeparation no/g" /etc/ssh/sshd_config \
    && sed -i "s/PermitRootLogin without-password/PermitRootLogin yes/" /etc/ssh/sshd_config \
    && mkdir -p /var/run/sshd

# Cache para el modulo de FTP (descargar e instalar)
RUN apt-get install -y vsftpd

# Expone el puerto del servicio en cuestion
EXPOSE 22

# Copia los archivos que harán parte de la imagen
COPY entry.sh /

# Primer comando que se ejecutara
ENTRYPOINT ["/entry.sh"]
