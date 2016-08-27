# -*- coding: utf-8 -*-
"""
Modulo SSL
"""

# standard imports
import logging

# 3rd party imports
import ssl
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

# local imports
# None

PORT = 443

def is_cert_cn_equal_to_site(site, port=PORT):
    """
    Function to check wether cert cn is equal to site
    """
    result = True
    cert = str(ssl.get_server_certificate((site, port)))
    cert_obj = load_pem_x509_certificate(cert, default_backend())
    cert_cn = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    wildcard_site = '*.' + site
    if site != cert_cn and wildcard_site != cert_cn:
        logging.info('%s CN equals to site, Details=%s, %s',
                     cert_cn, site, 'OPEN')
        result = True
    else:
        logging.info('%s CN equals to site, Details=%s, %s',
                     cert_cn, site, 'CLOSE')
        result = False
    return result

