# Imagen base oficial del linux mas seguro y pequeno
FROM alpine:3.4

# Dudas sobre la imagen en cuestion
MAINTAINER FLUID Engineering Team <engineering@fluid.la>

# Instala ssh python para administracion por ansible
RUN apk update \
    && apk upgrade \
    && apk add --no-cache openssh python \
    && ssh-keygen -A \
    && sed -i s/#PermitRootLogin.*/PermitRootLogin\ yes/ \
              /etc/ssh/sshd_config \
    && sed -i s/#PasswordAuthentication.*/PasswordAuthentication\ no/ \
              /etc/ssh/sshd_config \
    && rm -rf /var/cache/apk/*

# Copiar claves que permitan conexion sin password a ansible para gestion
# Estas claves fueron generados asi
# $ ssh-keygen -t rsa -f ansible_id_rsa -P "
# $ chmod 600 ansible_id_rsa.pub
COPY ansible_id_rsa.pub /root/.ssh/authorized_keys

# Expone el puerto del servicio en cuestion
EXPOSE 22

# Copia los archivos de configuracion del mock en la imagen
COPY entry.sh /

# Primer comando que se ejecutara por completo
ENTRYPOINT ["/entry.sh"]
