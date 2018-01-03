FROM alpine:latest 

ENV FLAVOR weak

EXPOSE 20/tcp 21/tcp 

RUN apk update && apk upgrade && apk add vsftpd 

COPY etc_vsftpd_conf.weak /etc/vsftpd/vsftpd.conf
COPY chroot_list /etc/vsftpd/chroot_list 
RUN mkdir -p /var/run/vsftpd/empty
RUN sed -i -e 's/pam_unix.so.*nullok_secure/pam_unix.so nullok/g' /etc/pam.d/base-auth
RUN sed -i -e 's/pam_unix.so.*obscure/pam_unix.so nullok obscure/g' /etc/pam.d/base-password
RUN (echo ahViQu9E; sleep 1; echo ahViQu9E) | adduser -s /bin/sh ftpsecure && mkdir -p /home/ftpsecure && chown ftpsecure: /home/ftpsecure
RUN (echo guessed123; sleep 1; echo guessed123) | adduser -s /bin/sh guessed && mkdir -p /home/guessed && chown guessed: /home/guessed
RUN (echo ahViQu9E; sleep 1; echo ahViQu9E) | adduser -s /bin/sh nonpass && mkdir -p /home/nonpass && chown nonpass: /home/nonpass
RUN passwd -d nonpass

CMD /usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf
