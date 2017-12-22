FROM debian:stable-slim

ENV FLAVOR weak

EXPOSE 25/tcp 

RUN apt-get update -qq && \
    apt-get install -y postfix

COPY etc_postfix_main.cf-weak /etc/postfix/main.cf

ENTRYPOINT ["/usr/lib/postfix/sbin/master", "-c", "/etc/postfix", "-d"]
