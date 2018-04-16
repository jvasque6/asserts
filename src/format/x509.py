# -*- coding: utf-8 -*-
"""X509 certificates module."""

# standard imports
from __future__ import absolute_import
import datetime
import socket
import ssl

# 3rd party imports
import tlslite
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track
from fluidasserts.helper.ssl_helper import connect as connect
from fluidasserts.helper.ssl_helper import connect_legacy as connect_legacy

PORT = 443


def __uses_sign_alg(site, alg, port):
    """Check whether cert use a hash method in their signature."""
    result = True

    try:
        with connect(site, port=port) as connection:
            __cert = connection.session.serverCertChain.x509List[0].bytes
            cert = ssl.DER_cert_to_PEM_cert(__cert)
    except socket.error:
        show_unknown('Port closed', details='Site="{}:{}"'.
                     format(site, port))
        return False
    except tlslite.errors.TLSRemoteAlert:
        try:
            with connect_legacy(site, port) as conn:
                __cert = conn.getpeercert(True)
                cert = ssl.DER_cert_to_PEM_cert(__cert)
        except socket.error:
            show_unknown('Port closed', details='Site="{}:{}"'.
                         format(site, port))
            return False
    cert_obj = load_pem_x509_certificate(cert.encode('utf-8'),
                                         default_backend())

    sign_algorith = cert_obj.signature_hash_algorithm.name

    if alg in sign_algorith:
        show_open('Certificate has {} as signature algorithm'.
                  format(sign_algorith.upper()),
                  details='Site="{}:{}"'.format(site, port))
        result = True
    else:
        show_close('Certificate does not use {} as signature algorithm'.
                   format(alg.upper()),
                   details='Site="{}:{}" uses "{}"'.
                   format(site, port, sign_algorith.upper()))
        result = False
    return result


@track
def is_cert_cn_not_equal_to_site(site, port=PORT):
    """Check whether cert cn is equal to site."""
    result = True
    has_sni = False
    try:
        with connect(site, port=port) as conn:
            __cert = conn.session.serverCertChain.x509List[0].bytes
            cert = ssl.DER_cert_to_PEM_cert(__cert)
    except socket.error:
        show_unknown('Port closed', details='Site="{}:{}"'.
                     format(site, port))
        return False
    except tlslite.errors.TLSRemoteAlert:
        try:
            with connect_legacy(site, port) as conn:
                __cert = conn.getpeercert(True)
                cert = ssl.DER_cert_to_PEM_cert(__cert)
                has_sni = True
        except socket.error:
            show_unknown('Port closed', details='Site="{}:{}"'.
                         format(site, port))
            return False

    cert_obj = load_pem_x509_certificate(cert.encode('utf-8'),
                                         default_backend())
    cert_cn = \
        cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
            0].value.lower()

    wc_cert = '*.' + site.lower()

    domain = 'NONE'
    if cert_cn.startswith('*.'):
        domain = '.' + cert_cn.split('*.')[1].lower()

    if site.lower() != cert_cn and wc_cert != cert_cn \
        and not site.endswith(domain):
        if has_sni:
            show_close('{} CN not equals to site. However server \
supports SNI'.format(cert_cn), details='Site="{}:{}", CN="{}"'.
                       format(site, port, cert_cn))
            result = False
        else:
            show_open('{} CN not equals to site'.format(cert_cn),
                      details='Site="{}:{}", CN="{}"'.
                      format(site, port, cert_cn))
            result = True
    else:
        show_close('{} CN equals to site'.format(cert_cn),
                   details='Site="{}:{}", CN="{}"'.
                   format(site, port, cert_cn))
        result = False
    return result


@track
def is_cert_inactive(site, port=PORT):
    """Check whether cert is still valid."""
    result = True
    try:
        with connect(site, port=port) as conn:
            __cert = conn.session.serverCertChain.x509List[0].bytes
            cert = ssl.DER_cert_to_PEM_cert(__cert)
    except socket.error:
        show_unknown('Port closed', details='Site="{}:{}"'.
                     format(site, port))
        return False
    except tlslite.errors.TLSRemoteAlert:
        try:
            with connect_legacy(site, port) as conn:
                __cert = conn.getpeercert(True)
                cert = ssl.DER_cert_to_PEM_cert(__cert)
        except socket.error:
            show_unknown('Port closed', details='Site="{}:{}"'.
                         format(site, port))
            return False

    cert_obj = load_pem_x509_certificate(cert.encode('utf-8'),
                                         default_backend())

    if cert_obj.not_valid_after > datetime.datetime.now():
        show_close('Certificate is still valid',
                   details='Site="{}:{}", Cert not valid after: {}, \
Current time: {}'.format(site, port, cert_obj.not_valid_after.isoformat(),
                         datetime.datetime.now().isoformat()))
        result = False
    else:
        show_open('Certificate is expired',
                  details='Site="{}:{}", Cert not valid after: {}, \
Current time: {}'.format(site, port, cert_obj.not_valid_after.isoformat(),
                         datetime.datetime.now().isoformat()))
        result = True
    return result


@track
def is_cert_validity_lifespan_unsafe(site, port=PORT):
    """Check whether cert lifespan is safe."""
    max_validity_days = 730

    result = True
    try:
        with connect(site, port=port) as conn:
            __cert = conn.session.serverCertChain.x509List[0].bytes
            cert = ssl.DER_cert_to_PEM_cert(__cert)
    except socket.error:
        show_unknown('Port closed', details='Site="{}:{}"'.
                     format(site, port))
        return False
    except tlslite.errors.TLSRemoteAlert:
        try:
            with connect_legacy(site, port) as conn:
                __cert = conn.getpeercert(True)
                cert = ssl.DER_cert_to_PEM_cert(__cert)
        except socket.error:
            show_unknown('Port closed', details='Site="{}:{}"'.
                         format(site, port))
            return False

    cert_obj = load_pem_x509_certificate(cert.encode('utf-8'),
                                         default_backend())

    cert_validity = \
        cert_obj.not_valid_after - cert_obj.not_valid_before

    if cert_validity.days <= max_validity_days:
        show_close('Certificate has a secure lifespan',
                   details='Site="{}:{}", Cert not valid before: {}, \
not valid after: {}'.format(site, port,
                            cert_obj.not_valid_before.isoformat(),
                            cert_obj.not_valid_after.isoformat()))
        result = False
    else:
        show_open('Certificate has an insecure lifespan',
                  details='Site="{}:{}", Cert not valid before: {}, \
not valid after: {}'.format(site, port,
                            cert_obj.not_valid_before.isoformat(),
                            cert_obj.not_valid_after.isoformat()))
        result = True
    return result


@track
def is_sha1_used(site, port=PORT):
    """Check whether cert use SHA1 in their signature algorithm."""
    return __uses_sign_alg(site, 'sha1', port)


@track
def is_md5_used(site, port=PORT):
    """Check whether cert use MD5 in their signature algorithm."""
    return __uses_sign_alg(site, 'md5', port)
