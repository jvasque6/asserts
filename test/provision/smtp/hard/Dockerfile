FROM registry.gitlab.com/fluidsignal/asserts/mocks/smtp:weak

ENV FLAVOR hard

EXPOSE 25/tcp

COPY etc_postfix_main.cf-hard /etc/postfix/main.cf

ENTRYPOINT ["/usr/lib/postfix/master", "-c", "/etc/postfix", "-d"]
