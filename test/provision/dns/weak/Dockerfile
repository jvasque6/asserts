FROM debian:stable-slim

ENV FLAVOR weak 

EXPOSE 53/tcp 53/udp

RUN apt-get update -qq && \
    apt-get install -y bind9 

COPY db.test.weak /var/cache/bind/db.test
COPY named.conf.options.weak /etc/bind/named.conf.options
COPY named.conf.local.weak /etc/bind/named.conf.local 

RUN chown bind: /var/cache/bind/db.test.signed

ENTRYPOINT ["/usr/sbin/named", "-g"]
