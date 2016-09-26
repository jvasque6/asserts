# -*- coding: utf-8 -*-
"""
Modulo SSL
"""

# standard imports
import logging
import socket

# 3rd party imports
import ssl

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID

# local imports
# None

PORT = 443


def is_cert_cn_equal_to_site(site, port=PORT):
    """
    Function to check whether cert cn is equal to site
    """
    result = True
    cert = str(ssl.get_server_certificate((site, port)))
    cert_obj = load_pem_x509_certificate(cert, default_backend())
    cert_cn = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
        0].value
    wildcard_site = '*.' + site
    if site != cert_cn and wildcard_site != cert_cn:
        logging.info('%s CN not equals to site, Details=%s, %s',
                     cert_cn, site, 'OPEN')
        result = True
    else:
        logging.info('%s CN equals to site, Details=%s, %s',
                     cert_cn, site, 'CLOSE')
        result = False
    return result


def is_pfs_enabled(site, port=PORT):
    """
    Function to check whether PFS is enabled
    """
    packet = '<packet>SOME_DATA</packet>'

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    ciphers = 'ECDHE-RSA-AES256-GCM-SHA384:\
               ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:\
               ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:\
               ECDHE-ECDSA-AES256-SHA:DHE-DSS-AES256-GCM-SHA384:\
               DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:\
               DHE-DSS-AES256-SHA256:DHE-RSA-AES256-SHA:\
               DHE-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:\
               DHE-DSS-CAMELLIA256-SHA:ECDHE-RSA-AES128-GCM-SHA256:\
               ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:\
               ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:\
               ECDHE-ECDSA-AES128-SHA:DHE-DSS-AES128-GCM-SHA256:\
               DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:\
               DHE-DSS-AES128-SHA256:DHE-RSA-AES128-SHA:\
               DHE-DSS-AES128-SHA:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:\
               DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:\
               ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:\
               ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA'

    wrapped_socket = ssl.wrap_socket(sock,
                                     ssl_version=ssl.PROTOCOL_TLSv1,
                                     ciphers=ciphers)

    result = True
    try:
        wrapped_socket.connect((site, port))
        wrapped_socket.send(packet)
        logging.info('PFS enabled on site, Details=%s, %s',
                     site, 'CLOSE')
        result = False
    except ssl.SSLError:
        logging.info('PFS not enabled on site, Details=%s, %s',
                     site, 'OPEN')
        result = True
    except socket.error:
        logging.info('Port is closed for PFS check, Details=%s, %s',
                     site, 'CLOSE')
        result = False
    finally:
        wrapped_socket.close()
    return result
