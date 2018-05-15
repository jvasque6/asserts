FROM registry.gitlab.com/fluidsignal/asserts:runner

ADD exploit.py /
ADD entrypoint.sh /
RUN chmod 0755 /entrypoint.sh

WORKDIR /code

CMD "/entrypoint.sh"
