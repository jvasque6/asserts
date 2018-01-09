FROM alpine:latest

RUN apk update && apk upgrade && apk add openssh clamav sudo
RUN ssh-keygen -A && \
    adduser -D -s /bin/sh nonpriv && \
    echo "root:Puef8poh2tei9AeB" | chpasswd && \
    echo "nonpriv:ahgh7xee9eewaeGh" | chpasswd && \
    sed -i -e 's/^umask.*/umask 0027/g' /etc/profile && \
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config

CMD /usr/sbin/sshd -D
