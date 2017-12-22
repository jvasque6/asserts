FROM registry.gitlab.com/fluidsignal/asserts/mocks/dns:weak 

RUN apt-get update -qq && \
    apt-get install -y bind9 

COPY db.test.signed /var/cache/bind/db.test.signed
COPY named.conf.options.hard /etc/bind/named.conf.options
COPY named.conf.local.hard /etc/bind/named.conf.local 
COPY Kfluid.la.+007+14480.ky /var/cache/bind
COPY Kfluid.la.+007+14480.private /var/cache/bind
COPY Kfluid.la.+007+26391.ky /var/cache/bind
COPY Kfluid.la.+007+26391.private /var/cache/bind

RUN chown bind: /var/cache/bind/Kfluid* && \
    chown bind: /var/cache/bind/db.test.signed && \
    chmod 600 /var/cache/bind/Kfluid*
    
ENTRYPOINT ["/usr/sbin/named", "-g"]
