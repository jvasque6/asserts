# Imagen base oficial del linux mas seguro y pequeno
FROM alpine:3.4

# Parametro de configuracion de inicio del mock
# ENV FLAVOR hardened # Inicia el servicio con configuracion segura (defecto)
# ENV FLAVOR vulnerable # Inicia el servicio con configuracion vulnerable
ENV FLAVOR hardened

# Adiciona el servidor LDAP
RUN apk update \
    && apk upgrade \
    && apk add --no-cache openldap openldap-clients openldap-back-hdb openldap-back-bdb ldapvi \
    && rm -rf /var/cache/apk/*

# Expone los puertos LDAP
EXPOSE 389 636

# Copia los archivos de configuracion del mock en la imagen
COPY entry.sh /

# Primer comando que se ejecutara por completo
ENTRYPOINT ["/entry.sh"]
