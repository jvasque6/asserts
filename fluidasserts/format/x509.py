# -*- coding: utf-8 -*-
"""This module allows to check ``X509`` certificates' vulnerabilities."""

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
from fluidasserts.utils.decorators import track, level
from fluidasserts.helper.ssl_helper import connect
from fluidasserts.helper.ssl_helper import connect_legacy

PORT = 443


def _uses_sign_alg(site: str, alg: str, port: int) -> bool:
    """
    Check if the given hashing method was used in signing the site certificate.

    :param site: Address to connect to.
    :param alg: Hashing method to test.
    :param port: Port to connect to.
    """
    result = True

    try:
        with connect(site, port=port) as connection:
            __cert = connection.session.serverCertChain.x509List[0].bytes
            cert = ssl.DER_cert_to_PEM_cert(__cert)
    except socket.error:
        show_unknown('Port closed', details=dict(site=site, port=port))
        return False
    except tlslite.errors.TLSRemoteAlert:
        try:
            with connect_legacy(site, port) as conn:
                __cert = conn.getpeercert(True)
                cert = ssl.DER_cert_to_PEM_cert(__cert)
        except socket.error:
            show_unknown('Port closed', details=dict(site=site, port=port))
            return False
    cert_obj = load_pem_x509_certificate(cert.encode('utf-8'),
                                         default_backend())

    sign_algorith = cert_obj.signature_hash_algorithm.name

    if alg in sign_algorith:
        show_open('Certificate has {} as signature algorithm'.
                  format(sign_algorith.upper()),
                  details=dict(site=site, port=port))
        result = True
    else:
        show_close('Certificate does not use {} as signature algorithm'.
                   format(alg.upper()),
                   details=dict(site=site, port=port,
                                algorithm=sign_algorith.upper()))
        result = False
    return result


@level('medium')
@track
def is_cert_cn_not_equal_to_site(site: str, port: int = PORT) -> bool:
    """
    Check if certificate Common Name (CN) is different from given sitename.

    Name in certificate should be coherent with organization name, see
    `REQ. 093 <https://fluidattacks.com/web/es/rules/093/>`_

    :param site: Site address.
    :param port: Port to connect to.
    """
    result = True
    has_sni = False
    try:
        with connect(site, port=port) as conn:
            __cert = conn.session.serverCertChain.x509List[0].bytes
            cert = ssl.DER_cert_to_PEM_cert(__cert)
    except socket.error:
        show_unknown('Port closed', details=dict(site=site, port=port))
        return False
    except tlslite.errors.TLSRemoteAlert:
        try:
            with connect_legacy(site, port) as conn:
                __cert = conn.getpeercert(True)
                cert = ssl.DER_cert_to_PEM_cert(__cert)
                has_sni = True
        except socket.error:
            show_unknown('Port closed', details=dict(site=site, port=port))
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

    if (site.lower() != cert_cn and wc_cert != cert_cn and
            not site.endswith(domain)):
        if has_sni:
            msg = '{} CN not equals to site. However server supports SNI'
            show_close(msg.format(cert_cn),
                       details=dict(site=site, port=port, cn=cert_cn))
            result = False
        else:
            show_open('{} CN not equals to site'.format(cert_cn),
                      details=dict(site=site, port=port, cn=cert_cn))
            result = True
    else:
        show_close('{} CN equals to site'.format(cert_cn),
                   details=dict(site=site, port=port, cn=cert_cn))
        result = False
    return result


@level('medium')
@track
def is_cert_inactive(site: str, port: int = PORT) -> bool:
    """
    Check if certificate is no longer valid.

    Fails if end of validity date obtained from certificate
    is beyond the time of execution.

    :param site: Site address.
    :param port: Port to connect to.
    """
    result = True
    try:
        with connect(site, port=port) as conn:
            __cert = conn.session.serverCertChain.x509List[0].bytes
            cert = ssl.DER_cert_to_PEM_cert(__cert)
    except socket.error:
        show_unknown('Port closed', details=dict(site=site, port=port))
        return False
    except tlslite.errors.TLSRemoteAlert:
        try:
            with connect_legacy(site, port) as conn:
                __cert = conn.getpeercert(True)
                cert = ssl.DER_cert_to_PEM_cert(__cert)
        except socket.error:
            show_unknown('Port closed', details=dict(site=site, port=port))
            return False

    cert_obj = load_pem_x509_certificate(cert.encode('utf-8'),
                                         default_backend())

    if cert_obj.not_valid_after > datetime.datetime.now():
        show_close('Certificate is still valid',
                   details=dict(site=site, port=port,
                                not_valid_after=cert_obj.not_valid_after.
                                isoformat(),
                                current_time=datetime.datetime.now().
                                isoformat()))
        result = False
    else:
        show_open('Certificate is expired',
                  details=dict(site=site, port=port,
                               not_valid_after=cert_obj.not_valid_after.
                               isoformat(),
                               current_time=datetime.datetime.now().
                               isoformat()))
        result = True
    return result


@level('medium')
@track
def is_cert_validity_lifespan_unsafe(site: str, port: int = PORT) -> bool:
    """
    Check if certificate lifespan is larger than two years which is insecure.

    :param site: Site address.
    :param port: Port to connect to.
    """
    max_validity_days = 730

    result = True
    try:
        with connect(site, port=port) as conn:
            __cert = conn.session.serverCertChain.x509List[0].bytes
            cert = ssl.DER_cert_to_PEM_cert(__cert)
    except socket.error:
        show_unknown('Port closed', details=dict(site=site, port=port))
        return False
    except tlslite.errors.TLSRemoteAlert:
        try:
            with connect_legacy(site, port) as conn:
                __cert = conn.getpeercert(True)
                cert = ssl.DER_cert_to_PEM_cert(__cert)
        except socket.error:
            show_unknown('Port closed', details=dict(site=site, port=port))
            return False

    cert_obj = load_pem_x509_certificate(cert.encode('utf-8'),
                                         default_backend())

    cert_validity = \
        cert_obj.not_valid_after - cert_obj.not_valid_before

    if cert_validity.days <= max_validity_days:
        show_close('Certificate has a secure lifespan',
                   details=dict(site=site, port=port,
                                not_valid_before=cert_obj.not_valid_before.
                                isoformat(),
                                not_valid_after=cert_obj.not_valid_after.
                                isoformat(),
                                max_validity_days=max_validity_days,
                                cert_validity_days=cert_validity.days))
        result = False
    else:
        show_open('Certificate has an insecure lifespan',
                  details=dict(site=site, port=port,
                               not_valid_before=cert_obj.not_valid_before.
                               isoformat(),
                               not_valid_after=cert_obj.not_valid_after.
                               isoformat(),
                               max_validity_days=max_validity_days,
                               cert_validity_days=cert_validity.days))
        result = True
    return result


@level('medium')
@track
def is_sha1_used(site: str, port: int = PORT) -> bool:
    """
    Check if certificate was signed using the ``SHA1`` algorithm.

    Use of this algorithm is not recommended.
    See `Storing passwords safely`__.

    __ https://fluidattacks.com/web/en/blog/storing-password-safely/

    :param site: Site address.
    :param port: Port to connect to.
    """
    return _uses_sign_alg(site, 'sha1', port)


@level('medium')
@track
def is_md5_used(site: str, port: int = PORT) -> bool:
    """
    Check if certificate was signed using the ``MD5`` algorithm.

    Use of this algorithm is not recommended.
    See `Storing passwords safely`__.

    __ https://fluidattacks.com/web/en/blog/storing-password-safely/

    :param site: Site address.
    :param port: Port to connect to.
    """
    return _uses_sign_alg(site, 'md5', port)
