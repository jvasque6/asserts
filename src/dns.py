# -*- coding: utf-8 -*-
"""
DNS check module
"""

# standard imports
import logging

# 3rd party imports
import dns.query
import dns.zone
from dns.exception import DNSException
from dns.zone import BadZone, NoSOA, NoNS, UnknownOrigin

# local imports
# None


def is_xfr_enabled(domain, nameserver):
    axfr_query = dns.query.xfr(nameserver, domain, timeout=5,
                               relativize=False, lifetime=10)

    result = True
    try:
        zone = dns.zone.from_xfr(axfr_query, relativize=False)
        if not str(zone.origin).rstrip('.'):
            result = False
        result = True
    except NoSOA:
        result = False
    except NoNS:
        result = False
    except BadZone:
        result = False
    except UnknownOrigin:
        result = False
    except DNSException:
        result = False

    return result
