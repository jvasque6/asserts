FROM registry.gitlab.com/fluidsignal/asserts/mocks/smtp:weak 

COPY etc_postfix_main.cf-hard /etc/postfix/main.cf

ENTRYPOINT ["/usr/lib/postfix/sbin/master", "-c", "/etc/postfix", "-d"]
