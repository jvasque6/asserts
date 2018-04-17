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
            show_close('Zone transfer not enabled on server',
                       details=dict(domain=domain, nameserver=nameserver))
            result = False
        result = True
        show_open('Zone transfer enabled on server', details='{}:{}'.
                  format(domain, nameserver))
    except (NoSOA, NoNS, BadZone, dns.query.BadResponse, DNSException):
        show_close('Zone transfer not enabled on server',
                   details=dict(domain=domain, nameserver=nameserver))
        result = False
    except socket.error:
        show_unknown('Port closed for zone transfer',
                     details=dict(domain=domain, nameserver=nameserver))
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
            show_close('Zone update not enabled on server',
                       details=dict(domain=domain, nameserver=nameserver))
            result = False
        else:
            show_open('Zone update enabled on server',
                      details=dict(domain=domain, nameserver=nameserver))
            result = True
    except dns.query.BadResponse:
        show_close('Zone update not enabled on server',
                   details=dict(domain=domain, nameserver=nameserver))
        result = False
    except socket.error:
        show_unknown('Port closed for DNS update',
                     details=dict(domain=domain, nameserver=nameserver))
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
        show_open('Cache poisoning is possible on server',
                  details=dict(domain=domain, nameserver=nameserver))
        return True

    if response.response.rcode() != 0:
        show_open('Cache poisoning is possible on server',
                  details=dict(domain=domain, nameserver=nameserver))
        result = True
    else:
        answer = response.rrset
        if len(answer) != 2:
            show_open('Cache poisoning possible on server',
                      details=dict(domain=domain, nameserver=nameserver))
            return True
        else:
            show_close('Cache poisoning not possible on server',
                       details=dict(domain=domain, nameserver=nameserver))
            result = False

    return result


@track
def has_cache_snooping(nameserver):
    """Check if nameserver has cache snooping.

    (supports non recursive queries)
    """
    domain = 'isc.org.'
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
            show_open('Cache snooping possible on server',
                      details=dict(domain=domain, nameserver=nameserver))
            result = True
        else:
            show_close('Cache snooping not possible on server',
                       details=dict(domain=domain, nameserver=nameserver))
            result = False
    except dns.exception.SyntaxError:
        show_close('Cache snooping not possible on server',
                   details=dict(domain=domain, nameserver=nameserver))
        result = False

    return result


@track
def has_recursion(nameserver):
    """Check if nameserver has recursion enabled."""
    domain = 'isc.org.'
    name = dns.name.from_text(domain)

    try:
        # Make a recursive request
        request = dns.message.make_query(name, dns.rdatatype.A,
                                         dns.rdataclass.IN)

        response = dns.query.udp(request, nameserver)

        result = True
        if response.rcode() == 0:
            show_open('Recursion possible on server',
                      details=dict(domain=domain, nameserver=nameserver))
            result = True
        else:
            show_close('Recursion not possible on server',
                       details=dict(domain=domain, nameserver=nameserver))
            result = False
    except dns.exception.SyntaxError:
        show_close('Recursion not possible on server',
                   details=dict(domain=domain, nameserver=nameserver))
        result = False

    return result


@track
def can_amplify(nameserver):
    """Checks if nameserver allows amplification attacks."""
    domain = 'isc.org.'
    name = dns.name.from_text(domain)

    try:
        # Make a recursive request
        request = dns.message.make_query(name, dns.rdatatype.A,
                                         dns.rdataclass.IN)
        response = dns.query.udp(request, nameserver)
        if response.rcode() == 0:
            request = dns.message.make_query(name, dns.rdatatype.ANY)
            request.flags |= dns.flags.AD
            request.find_rrset(request.additional, dns.name.root, 65535,
                               dns.rdatatype.OPT, create=True,
                               force_unique=True)
            response = dns.query.udp(request, nameserver)
            resp_len = sum([len(x.to_text()) for x in response.answer])
            req_len = len(request.to_text())
            if req_len < resp_len:
                show_open('Amplification attack is possible on server',
                          details=dict(nameserver=nameserver,
                                       request_len=req_len,
                                       response_len=resp_len))
                return True
        show_close('Amplification attack is not possible on server',
                   details=dict(nameserver=nameserver))
        return False
    except dns.exception.SyntaxError:
        show_close('Amplification attack is not possible on server',
                   details=dict(nameserver=nameserver))
        return False
