FROM registry.gitlab.com/fluidsignal/asserts/mocks/dns:weak 

ENV FLAVOR hard

EXPOSE 53/tcp 53/udp

COPY $PWD/named.conf /etc/bind/named.conf
COPY $PWD/named.conf.options.hard /etc/bind/named.conf.options
COPY $PWD/named.conf.local.hard /etc/bind/named.conf.local 
COPY $PWD/Kfluid.la.+007+14480.ky /var/bind
COPY $PWD/Kfluid.la.+007+14480.private /var/bind
COPY $PWD/Kfluid.la.+007+26391.ky /var/bind
COPY $PWD/Kfluid.la.+007+26391.private /var/bind

RUN mkdir -p /var/bind
COPY db.test.signed /var/bind/db.test.signed
RUN chown root:named /var/bind/ /etc/bind -R && \
    chmod 600 /var/bind/Kfluid*
    
ENTRYPOINT ["/usr/sbin/named", "-g"]
