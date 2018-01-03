FROM alpine:latest 

ENV FLAVOR weak

EXPOSE 139/tcp 445/tcp 

RUN apk update && apk upgrade && apk add samba 

COPY etc_samba_smb.conf-weak /etc/samba/smb.conf

ENTRYPOINT ["/usr/sbin/smbd", "-F"]
