# -*- coding: utf-8 -*-
"""
DNS check module
"""

# standard imports
import logging

# 3rd party imports
import dns.query
from dns.exception import DNSException
import dns.zone
from dns.zone import BadZone
from dns.zone import NoSOA
from dns.zone import NoNS

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
