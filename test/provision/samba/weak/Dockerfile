FROM debian:stable-slim

ENV FLAVOR weak

EXPOSE 139/tcp 445/tcp 

RUN apt-get update -qq && \
    apt-get install -y samba 

COPY etc_samba_smb.conf-weak /etc/samba/smb.conf

ENTRYPOINT ["/usr/sbin/smbd", "-F"]
