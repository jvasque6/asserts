FROM debian:stable-slim

RUN apt-get update -qq && \
    apt-get install -y samba 

COPY etc_samba_smb.conf-weak /etc/samba/smb.conf

ENTRYPOINT ["/usr/sbin/smbd", "-F"]
