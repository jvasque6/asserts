# -*- coding: utf-8 -*-
"""DNS check module."""

# standard imports
from __future__ import absolute_import

# 3rd party imports
import socket
import dns.dnssec
from dns.exception import DNSException
import dns.query
import dns.rdatatype
import dns.resolver
import dns.update
import dns.zone
from dns.zone import BadZone
from dns.zone import NoNS
from dns.zone import NoSOA


# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts import LOGGER
from fluidasserts.utils.decorators import track


@track
def is_xfr_enabled(domain, nameserver):
    """Check if zone transfer is enabled."""
    axfr_query = dns.query.xfr(nameserver, domain, timeout=5,
                               relativize=False, lifetime=10)

    result = True
    try:
        zone = dns.zone.from_xfr(axfr_query, relativize=False)
        if not str(zone.origin).rstrip('.'):
            LOGGER.info('%s: Zone transfer not enabled on server, \
Details=%s:%s',
                        show_close(), domain, nameserver)
            result = False
        result = True
        LOGGER.info('%s: Zone transfer enabled on server, Details=%s:%s',
                    show_open(), domain, nameserver)
    except NoSOA:
        LOGGER.info('%s: Zone transfer not enabled on server, Details=%s:%s',
                    show_close(), domain, nameserver)
        result = False
    except NoNS:
        LOGGER.info('%s: Zone transfer not enabled on server, Details=%s:%s',
                    show_close(), domain, nameserver)
        result = False
    except BadZone:
        LOGGER.info('%s: Zone transfer not enabled on server, Details=%s:%s',
                    show_close(), domain, nameserver)
        result = False
    except dns.query.BadResponse:
        LOGGER.info('%s: Zone transfer not enabled on server, Details=%s:%s',
                    show_close(), domain, nameserver)
        result = False
    except DNSException:
        LOGGER.info('%s: Zone transfer not enabled on server, Details=%s:%s',
                    show_close(), domain, nameserver)
        result = False
    except socket.error:
        LOGGER.info('%s: Port closed for zone transfer, Details=%s:%s',
                    show_unknown(), domain, nameserver)
        result = False

    return result


@track
def is_dynupdate_enabled(domain, nameserver):
    """Check if zone updating is enabled."""
    newrecord = 'newrecord'

    try:
        update = dns.update.Update(domain)
        update.add(newrecord, 3600, dns.rdatatype.A, '10.10.10.10')
        response = dns.query.tcp(update, nameserver)

        result = True

        if response.rcode() > 0:
            LOGGER.info('%s: Zone update not enabled on server, \
    Details=%s:%s', show_close(), domain, nameserver)
            result = False
        else:
            LOGGER.info('%s: Zone update enabled on server, Details=%s:%s',
                        show_open(), domain, nameserver)
            result = True
    except dns.query.BadResponse:
        LOGGER.info('%s: Zone update not enabled on server, Details=%s:%s',
                    show_close(), domain, nameserver)
        result = False
    except socket.error:
        LOGGER.info('%s: Port closed for DNS update, Details=%s:%s',
                    show_unknown(), domain, nameserver)
        result = False
    return result


@track
def has_cache_poison(domain, nameserver):
    """Check if cache poisoning is possible.

    The check is made by looking DNSSEC records
    """
    myresolver = dns.resolver.Resolver()
    myresolver.nameservers = [nameserver]

    name = dns.name.from_text(domain)

    result = True
    try:
        response = myresolver.query(name, 'DNSKEY')
    except DNSException:
        LOGGER.info('%s: Cache poisoning is possible on server, \
Details=%s:%s', show_open(), domain, nameserver)
        return True

    if response.response.rcode() != 0:
        LOGGER.info('%s: Cache poisoning is possible on server, \
Details=%s:%s', show_open(), domain, nameserver)
        result = True
    else:
        answer = response.rrset
        if len(answer) != 2:
            LOGGER.info('%s: Cache poisoning possible on server, \
Details=%s:%s', show_open(), domain, nameserver)
            return True
        else:
            LOGGER.info('%s: Cache poisoning not possible on server, \
Details=%s:%s', show_close(), domain, nameserver)
            result = False

    return result


@track
def has_cache_snooping(nameserver):
    """Check if nameserver has cache snooping.

    (supports non recursive queries)
    """
    domain = 'google.com'
    name = dns.name.from_text(domain)

    try:
        # Make a recursive request to fill out the cache
        request = dns.message.make_query(name, dns.rdatatype.A,
                                         dns.rdataclass.IN)

        response = dns.query.udp(request, nameserver)

        # Make a non-recursive request
        request = dns.message.make_query(name, dns.rdatatype.A,
                                         dns.rdataclass.IN)
        request.flags ^= dns.flags.RD

        response = dns.query.udp(request, nameserver)

        result = True
        if response.rcode() == 0:
            LOGGER.info('%s: Cache snooping possible on server, \
Details=%s:%s', show_open(), domain, nameserver)
            result = True
        else:
            LOGGER.info('%s: Cache snooping not possible on server, \
Details=%s:%s', show_close(), domain, nameserver)
            result = False
    except dns.exception.SyntaxError:
        LOGGER.info('%s: Cache snooping not possible on server, \
Details=%s:%s', show_close(), domain, nameserver)
        result = False

    return result


@track
def has_recursion(nameserver):
    """Check if nameserver has recursion enabled."""
    domain = 'google.com'
    name = dns.name.from_text(domain)

    try:
        # Make a recursive request
        request = dns.message.make_query(name, dns.rdatatype.A,
                                         dns.rdataclass.IN)

        response = dns.query.udp(request, nameserver)

        result = True
        if response.rcode() == 0:
            LOGGER.info('%s: Recursion possible on server, \
Details=%s:%s', show_open(), domain, nameserver)
            result = True
        else:
            LOGGER.info('%s: Recursion not possible on server, \
Details=%s:%s', show_close(), domain, nameserver)
            result = False
    except dns.exception.SyntaxError:
        LOGGER.info('%s: Recursion not possible on server, \
Details=%s:%s', show_close(), domain, nameserver)
        result = False

    return result
