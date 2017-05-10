# -*- coding: utf-8 -*-
"""DNS check module."""

# standard imports
from __future__ import absolute_import
import logging

# 3rd party imports
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
import socket
from termcolor import colored

# local imports
# None

logger = logging.getLogger('FLUIDAsserts')


def is_xfr_enabled(domain, nameserver):
    """Check if zone transfer is enabled."""
    axfr_query = dns.query.xfr(nameserver, domain, timeout=5,
                               relativize=False, lifetime=10)

    result = True
    try:
        zone = dns.zone.from_xfr(axfr_query, relativize=False)
        if not str(zone.origin).rstrip('.'):
            logger.info('Zone transfer not enabled on server, \
Details=%s:%s, %s',
                        domain, nameserver, colored('CLOSE', 'green'))
            result = False
        result = True
        logger.info('Zone transfer enabled on server, Details=%s:%s, %s',
                    domain, nameserver, colored('OPEN', 'red'))
    except NoSOA:
        logger.info('Zone transfer not enabled on server, Details=%s:%s, %s',
                    domain, nameserver, colored('CLOSE', 'green'))
        result = False
    except NoNS:
        logger.info('Zone transfer not enabled on server, Details=%s:%s, %s',
                    domain, nameserver, colored('CLOSE', 'green'))
        result = False
    except BadZone:
        logger.info('Zone transfer not enabled on server, Details=%s:%s, %s',
                    domain, nameserver, colored('CLOSE', 'green'))
        result = False
    except DNSException:
        logger.info('Zone transfer not enabled on server, Details=%s:%s, %s',
                    domain, nameserver, colored('CLOSE', 'green'))
        result = False
    except dns.query.BadResponse:
        logger.info('Zone transfer not enabled on server, Details=%s:%s, %s',
                    domain, nameserver, 'CLOSE')
        result = False
    except socket.error:
        logger.info('Port closed for zone transfer, Details=%s:%s, %s',
                    domain, nameserver, colored('CLOSE', 'green'))
        result = False

    return result


def is_dynupdate_enabled(domain, nameserver):
    """Check if zone updating is enabled."""
    newrecord = 'newrecord'

    try:
        update = dns.update.Update(domain)
        update.add(newrecord, 3600, dns.rdatatype.A, '10.10.10.10')
        response = dns.query.tcp(update, nameserver)

        result = True

        if response.rcode() > 0:
            logger.info('Zone update not enabled on server, \
    Details=%s:%s, %s', domain, nameserver, colored('CLOSE', 'green'))
            result = False
        else:
            logger.info('Zone update enabled on server, Details=%s:%s, %s',
                        domain, nameserver, colored('OPEN', 'red'))
            result = True
    except dns.query.BadResponse:
        logger.info('Zone update not enabled on server, Details=%s:%s, %s',
                    domain, nameserver, 'CLOSE')
        result = False
    except socket.error:
        logger.info('Port closed for DNS update, Details=%s:%s, %s',
                    domain, nameserver, colored('CLOSE', 'green'))
        result = False
    return result


def has_cache_poison(domain, nameserver):
    """Function has_cache_poison.

    Checks if cache poisoning is possible.
    The check is made by looking DNSSEC records
    """
    myresolver = dns.resolver.Resolver()
    myresolver.nameservers = [nameserver]

    name = dns.name.from_text(domain)

    result = True
    try:
        response = myresolver.query(name, 'DNSKEY')
    except DNSException:
        logger.info('Cache poisonig is possible on server, \
Details=%s:%s, %s', domain, nameserver, colored('OPEN', 'red'))
        return True

    if response.response.rcode() != 0:
        logger.info('Cache poisonig is possible on server, \
Details=%s:%s, %s', domain, nameserver, colored('OPEN', 'red'))
        result = True
    else:
        answer = response.rrset
        if len(answer) != 2:
            logger.info('Cache poisonig possible on server, \
Details=%s:%s, %s', domain,
                        nameserver, colored('OPEN', 'red'))
            return True
        else:
            logger.info('Cache poisonig not possible on server, \
Details=%s:%s, %s', domain,
                        nameserver, colored('CLOSE', 'green'))
            result = False

    return result


def has_cache_snooping(nameserver):
    """Function has_cache_snooping.

    Checks if nameserver has cache snooping.
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
            logger.info('Cache snooping possible on server, \
Details=%s:%s, %s', domain,
                        nameserver, colored('OPEN', 'red'))
            result = True
        else:
            logger.info('Cache snooping not possible on server, \
Details=%s:%s, %s', domain,
                        nameserver, colored('CLOSE', 'green'))
            result = False
    except dns.exception.SyntaxError:
        logger.info('Cache snooping not possible on server, \
Details=%s:%s, %s', domain,
                    nameserver, colored('CLOSE', 'green'))
        result = False

    return result


def has_recursion(nameserver):
    """Function has_recursion.

    Checks if nameserver has recursion enabled.
    """
    domain = 'google.com'
    name = dns.name.from_text(domain)

    try:
        # Make a recursive request
        request = dns.message.make_query(name, dns.rdatatype.A,
                                         dns.rdataclass.IN)

        response = dns.query.udp(request, nameserver)

        result = True
        if response.rcode() == 0:
            logger.info('Recursion possible on server, \
Details=%s:%s, %s', domain,
                        nameserver, colored('OPEN', 'red'))
            result = True
        else:
            logger.info('Recursion not possible on server, \
Details=%s:%s, %s', domain,
                        nameserver, colored('CLOSE', 'green'))
            result = False
    except dns.exception.SyntaxError:
        logger.info('Recursion not possible on server, \
Details=%s:%s, %s', domain,
                    nameserver, colored('CLOSE', 'green'))
        result = False

    return result
