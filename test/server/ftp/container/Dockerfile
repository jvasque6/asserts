# Imagen base oficial del linux mas seguro y pequeno
FROM alpine:3.4

# Parametro de configuracion de inicio del mock
# ENV FLAVOR hardened # Inicia el servicio con configuracion segura (defecto)
# ENV FLAVOR vulnerable # Inicia el servicio con configuracion vulnerable
ENV FLAVOR hardened

RUN apk update \
    && apk upgrade \
    && apk add --no-cache vsftpd \
    && rm -rf /var/cache/apk/* \
    && adduser -D ftpsecure \
    && echo "root:root123" | chpasswd \
    && adduser -D -s /bin/ash faustino \
    && echo "faustino:faustino123" | chpasswd

# Expone el puerto del servicio en cuestion
EXPOSE 21 21000-21009

# Copia los archivos de configuracion del mock en la imagen
COPY entry.sh /
COPY vsftpd.conf.hardened /etc/vsftpd/
COPY vsftpd.conf.vulnerable /etc/vsftpd/
COPY vsftpd.chroot_list /etc/
COPY banner /etc/

# Primer comando que se ejecutara por completo
ENTRYPOINT ["/entry.sh"]
