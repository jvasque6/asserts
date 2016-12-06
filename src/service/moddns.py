# -*- coding: utf-8 -*-
"""
DNS check module
"""

# standard imports
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

# local imports
# None


def is_xfr_enabled(domain, nameserver):
    """Checks if zone transfer is enabled."""
    axfr_query = dns.query.xfr(nameserver, domain, timeout=5,
                               relativize=False, lifetime=10)

    result = True
    try:
        zone = dns.zone.from_xfr(axfr_query, relativize=False)
        if not str(zone.origin).rstrip('.'):
            logging.info('Zone transfer not enabled on server, \
                         Details=%s:%s, %s',
                         domain, nameserver, 'CLOSE')
            result = False
        result = True
        logging.info('Zone transfer enabled on server, Details=%s:%s, %s',
                     domain, nameserver, 'OPEN')
    except NoSOA:
        logging.info('Zone transfer not enabled on server, Details=%s:%s, %s',
                     domain, nameserver, 'CLOSE')
        result = False
    except NoNS:
        logging.info('Zone transfer not enabled on server, Details=%s:%s, %s',
                     domain, nameserver, 'CLOSE')
        result = False
    except BadZone:
        logging.info('Zone transfer not enabled on server, Details=%s:%s, %s',
                     domain, nameserver, 'CLOSE')
        result = False
    except DNSException:
        logging.info('Zone transfer not enabled on server, Details=%s:%s, %s',
                     domain, nameserver, 'CLOSE')
        result = False

    return result


def is_dynupdate_enabled(domain, nameserver):
    """Checks if zone updating is enabled."""
    newrecord = 'newrecord'

    update = dns.update.Update(domain)
    update.add(newrecord, 3600, dns.rdatatype.A, '10.10.10.10')
    response = dns.query.tcp(update, nameserver)

    result = True
    if response.rcode() > 0:
        logging.info('Zone update not enabled on server, \
                     Details=%s:%s, %s', domain, nameserver, 'CLOSE')
        result = False
    else:
        logging.info('Zone update enabled on server, Details=%s:%s, %s',
                     domain, nameserver, 'OPEN')
        result = True

    return result


def has_cache_poison(domain, nameserver):
    """
    Checks if cache poisoning is possible.
    The check is made by looking DNSSEC records
    """

    myresolver = dns.resolver.Resolver()
    myresolver.nameservers = [nameserver]

    name = dns.name.from_text(domain)

    result = True
    try:
        response = myresolver.query(name, 'DNSKEY')
    except Exception:
        logging.info('Cache poisonig is possible on server, \
                     Details=%s:%s, %s', domain, nameserver, 'OPEN')
        return True

    if response.response.rcode() != 0:
        logging.info('Cache poisonig is possible on server, \
                     Details=%s:%s, %s', domain, nameserver, 'OPEN')
        result = True
    else:
        answer = response.rrset
        if len(answer) != 2:
            logging.info('Cache poisonig possible on server, \
                         Details=%s:%s, %s', domain,
                         nameserver, 'OPEN')
            return True
        else:
            logging.info('Cache poisonig not possible on server, \
                         Details=%s:%s, %s', domain,
                         nameserver, 'CLOSE')
            result = False

    return result


def has_cache_snooping(nameserver):
    """Checks if nameserver has cache snooping
    (supports non recursive queries)"""

    domain = 'google.com'
    name = dns.name.from_text(domain)

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
        logging.info('Cache snooping possible on server, \
                     Details=%s:%s, %s', domain,
                     nameserver, 'OPEN')
        result = True
    else:
        logging.info('Cache snooping not possible on server, \
                     Details=%s:%s, %s', domain,
                     nameserver, 'CLOSE')
        result = False

    return result
