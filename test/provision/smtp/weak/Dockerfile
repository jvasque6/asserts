FROM alpine:latest

ENV FLAVOR weak

EXPOSE 25/tcp

RUN apk update && apk upgrade && apk add postfix

COPY etc_postfix_main.cf-weak /etc/postfix/main.cf

ENTRYPOINT ["/usr/lib/postfix/master", "-c", "/etc/postfix", "-d"]
