# -*- coding: utf-8 -*-
"""
DNS check module.

This module allows to check vulnerabilities in DNS systems.
"""

# standard imports
from __future__ import absolute_import

# 3rd party imports
import socket
import dns.dnssec
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
def is_xfr_enabled(domain: str, nameserver: str) -> bool:
    """
    Check if zone transfer is enabled.

    :param domain: Name of the zone to transfer.
    :param nameserver: IPv4 or 6 to test.
    """
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
        show_open('Zone transfer enabled on server',
                  details=dict(domain=domain, nameserver=nameserver))
    except (NoSOA, NoNS, BadZone, dns.query.BadResponse):
        show_close('Zone transfer not enabled on server',
                   details=dict(domain=domain, nameserver=nameserver))
        result = False
    except (socket.error, dns.exception.Timeout,
            dns.exception.FormError) as exc:
        show_unknown('Could not connect',
                     details=dict(domain=domain, nameserver=nameserver,
                                  error=str(exc).replace(':', ',')))
        result = False

    return result


@track
def is_dynupdate_enabled(domain: str, nameserver: str) -> bool:
    """
    Check if zone updating is enabled.

    :param domain: Name of the zone to transfer.
    :param nameserver: IPv4 or 6 to test.
    """
    newrecord = 'newrecord'

    try:
        update = dns.update.Update(domain)
        update.add(newrecord, 3600, dns.rdatatype.A, '10.10.10.10')
        response = dns.query.tcp(update, nameserver, timeout=5)

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
    except (socket.error, dns.exception.Timeout) as exc:
        show_unknown('Could not connect',
                     details=dict(domain=domain, nameserver=nameserver,
                                  error=str(exc).replace(':', ',')))
        result = False
    return result


@track
def has_cache_poison(domain: str, nameserver: str) -> bool:
    """
    Check if cache poisoning is possible.

    The check is made by looking DNSSEC records.

    :param domain: Name of the zone to transfer.
    :param nameserver: IPv4 or 6 to test.
    """
    myresolver = dns.resolver.Resolver()
    myresolver.nameservers = [nameserver]

    name = dns.name.from_text(domain)

    result = True
    try:
        response = myresolver.query(name, 'DNSKEY')
    except (dns.exception.Timeout, dns.exception.SyntaxError,
            dns.resolver.NoNameservers) as exc:
        show_unknown('Could not connect',
                     details=dict(domain=domain, nameserver=nameserver,
                                  error=str(exc).replace(':', ',')))
        return False
    except dns.resolver.NoAnswer:
        show_open('Cache poisoning possible on server',
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
def has_cache_snooping(nameserver: str) -> bool:
    """
    Check if nameserver has cache snooping.

    (supports non recursive queries)
    :param nameserver: IPv4 or 6 to test.
    """
    domain = 'isc.org.'
    name = dns.name.from_text(domain)

    try:
        # Make a recursive request to fill out the cache
        request = dns.message.make_query(name, dns.rdatatype.A,
                                         dns.rdataclass.IN)

        response = dns.query.udp(request, nameserver, timeout=5)

        # Make a non-recursive request
        request = dns.message.make_query(name, dns.rdatatype.A,
                                         dns.rdataclass.IN)
        request.flags ^= dns.flags.RD

        response = dns.query.udp(request, nameserver, timeout=5)

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
    except (socket.error, dns.exception.Timeout) as exc:
        show_unknown('Could not connect',
                     details=dict(domain=domain, nameserver=nameserver,
                                  error=str(exc).replace(':', ',')))
        result = False
    return result


@track
def has_recursion(nameserver: str) -> bool:
    """
    Check if nameserver has recursion enabled.

    :param nameserver: IPv4 or 6 to test.
    """
    domain = 'isc.org.'
    name = dns.name.from_text(domain)

    try:
        # Make a recursive request
        request = dns.message.make_query(name, dns.rdatatype.A,
                                         dns.rdataclass.IN)

        response = dns.query.udp(request, nameserver, timeout=5)
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
    except (socket.error, dns.exception.Timeout) as exc:
        show_unknown('Could not connect',
                     details=dict(domain=domain, nameserver=nameserver,
                                  error=str(exc).replace(':', ',')))
        result = False
    return result


@track
def can_amplify(nameserver: str) -> bool:
    """
    Check if nameserver allows amplification attacks.

    :param nameserver: IPv4 or 6 to test.
    """
    domain = 'isc.org.'
    name = dns.name.from_text(domain)

    try:
        # Make a recursive request
        request = dns.message.make_query(name, dns.rdatatype.A,
                                         dns.rdataclass.IN)
        response = dns.query.udp(request, nameserver, timeout=5)
        if response.rcode() == 0:
            request = dns.message.make_query(name, dns.rdatatype.ANY)
            request.flags |= dns.flags.AD
            request.find_rrset(request.additional, dns.name.root, 65535,
                               dns.rdatatype.OPT, create=True,
                               force_unique=True)
            response = dns.query.udp(request, nameserver, timeout=5)
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
    except (socket.error, dns.exception.Timeout) as exc:
        show_unknown('Could not connect',
                     details=dict(domain=domain, nameserver=nameserver,
                                  error=str(exc).replace(':', ',')))
        return False
