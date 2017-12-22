# Imagen base oficial del linux mas seguro y pequeno
# Para SSH esta imagen tiene el openssh compilado sin
# soporte SSH1
FROM alpine:3.4

# Parametro de configuracion de inicio del mock
# ENV FLAVOR hard # Inicia el servicio con configuracion segura (defecto)
# ENV FLAVOR weak # Inicia el servicio con configuracion vulnerable
ENV FLAVOR hard

# Adiciona el servidor SSH
# Genera todas las claves de host necesarias
RUN apk update \
    && apk upgrade \
    && apk add --no-cache openssh \
    && ssh-keygen -A \
    && rm -rf /var/cache/apk/* \
    && echo "root:root123" | chpasswd \
    && adduser -D -s /bin/ash faustino \
    && echo "faustino:faustino123" | chpasswd

# Expone el puerto de SSH al host
EXPOSE 22

# Copia los archivos de configuracion del mock en la imagen
COPY entry.sh /
COPY sshd_config.* /etc/ssh/
COPY banner /etc/

# Primer comando que se ejecutara por completo
ENTRYPOINT ["/entry.sh"]
