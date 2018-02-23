# -*- coding: utf-8 -*-
"""SSL module."""

# standard imports
from __future__ import absolute_import
from contextlib import contextmanager
import datetime
import socket
import ssl

# 3rd party imports
import certifi
import tlslite
from tlslite.constants import CipherSuite, GroupName
from tlslite.constants import ContentType, CertificateType
from tlslite.extensions import SupportedGroupsExtension
from tlslite.messages import RecordHeader3
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track
from fluidasserts.helper import http_helper

PORT = 443
CIPHER_SUITES = CipherSuite.tls12Suites
CIPHER_NAMES = ["chacha20-poly1305",
                "aes256gcm", "aes128gcm",
                "aes256", "aes128"]
KEY_EXCHANGE = ["rsa", "dhe_rsa", "ecdhe_rsa", "srp_sha", "srp_sha_rsa",
                "ecdh_anon", "dh_anon"]


def __my_add_padding(self, data):
    """Add padding to data so that it is multiple of block size."""
    current_length = len(data)
    block_length = self.blockSize
    padding_length = block_length - 1 - (current_length % block_length)
    padding_bytes = bytearray([padding_length] * (padding_length+1))
    padding_bytes = bytearray(x ^ 42 for x in padding_bytes[0:-1])
    padding_bytes.append(padding_length)
    data += padding_bytes
    return data


@contextmanager
def __connect_legacy(hostname, port=PORT, ciphers=None):
    """Establish a legacy SSL/TLS connection."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        wrapped_socket = ssl.SSLSocket(sock=sock,
                                       ca_certs=certifi.where(),
                                       cert_reqs=ssl.CERT_REQUIRED,
                                       server_hostname=hostname,
                                       ciphers=ciphers)
        wrapped_socket.connect((hostname, port))
        yield wrapped_socket
    except socket.error:
        raise
    finally:
        wrapped_socket.close()


# pylint: disable=too-many-arguments
@contextmanager
def __connect(hostname, port=PORT, check_poodle_tls=False,
              min_version=(3, 1),
              max_version=(3, 3),
              cipher_names=None,
              key_exchange_names=None,
              anon=False):
    """Establish a SSL/TLS connection."""

    if cipher_names is None:
        cipher_names = CIPHER_NAMES
    if key_exchange_names is None:
        key_exchange_names = KEY_EXCHANGE
    orig_method = tlslite.recordlayer.RecordLayer.addPadding
    if check_poodle_tls:
        tlslite.recordlayer.RecordLayer.addPadding = __my_add_padding
    else:
        tlslite.recordlayer.RecordLayer.addPadding = orig_method

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((hostname, port))
    except socket.error:
        raise
    try:
        connection = tlslite.TLSConnection(sock)

        settings = tlslite.HandshakeSettings()
        settings.minVersion = min_version
        settings.maxVersion = max_version
        settings.cipherNames = cipher_names
        settings.keyExchangeNames = key_exchange_names

        if anon:
            connection.handshakeClientAnonymous(settings=settings)
        else:
            connection.handshakeClientCert(settings=settings)
        yield connection
    finally:
        connection.close()


@contextmanager
def __tls_hello(hostname, port=PORT, version=(3, 3), cipher_suites=None):
    """Send a ClientHello message."""

    check_poodle_tls = False

    if cipher_suites is None:
        cipher_suites = CIPHER_SUITES
    orig_method = tlslite.recordlayer.RecordLayer.addPadding
    if check_poodle_tls:
        tlslite.recordlayer.RecordLayer.addPadding = __my_add_padding
    else:
        tlslite.recordlayer.RecordLayer.addPadding = orig_method

    try:
        ext = [SupportedGroupsExtension().create([GroupName.x25519,
                                                  GroupName.secp256r1,
                                                  GroupName.secp384r1,
                                                  GroupName.secp521r1,
                                                  GroupName.ffdhe2048,
                                                  GroupName.ffdhe3072,
                                                  GroupName.ffdhe4096,
                                                  GroupName.ffdhe6144,
                                                  GroupName.ffdhe8192])]
        hello = tlslite.messages.ClientHello()
        hello.create(version, tlslite.utils.cryptomath.getRandomBytes(32),
                     bytearray(0), cipher_suites,
                     certificate_types=[CertificateType.x509],
                     srpUsername=None, tack=False, supports_npn=False,
                     serverName=hostname, extensions=ext)
        hello_data = hello.write()
        header_data = RecordHeader3().create(version,
                                             ContentType.handshake,
                                             len(hello_data)).write()
        packet = header_data + hello_data
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((hostname, port))
        sock.send(packet)
        response = sock.recv(4096)
        if not response:
            raise tlslite.errors.TLSRemoteAlert

        packet_parser = tlslite.messages.Parser(bytearray(response))
        response_header = RecordHeader3()
        response_header.parse(packet_parser)
        if response_header.type == ContentType.alert:
            raise tlslite.errors.TLSRemoteAlert
        print('YAI')
        yield sock
    except socket.error:
        raise
    finally:
        sock.close()


def __uses_sign_alg(site, alg, port):
    """Check whether cert use a hash method in their signature."""
    result = True

    try:
        with __connect(site, port=port) as connection:
            __cert = connection.session.serverCertChain.x509List[0].bytes
            cert = ssl.DER_cert_to_PEM_cert(__cert)
    except socket.error:
        show_unknown('Port closed, Details={}:{}'.
                     format(site, port))
        return False
    except tlslite.errors.TLSRemoteAlert:
        try:
            with __connect_legacy(site, port) as conn:
                __cert = conn.getpeercert(True)
                cert = ssl.DER_cert_to_PEM_cert(__cert)
        except socket.error:
            show_unknown('Port closed, Details={}:{}'.
                         format(site, port))
            return False
    cert_obj = load_pem_x509_certificate(cert.encode('utf-8'),
                                         default_backend())

    sign_algorith = cert_obj.signature_hash_algorithm.name

    if alg in sign_algorith:
        show_open('Certificate has {} as signature algorithm, \
Details={}:{}'.format(sign_algorith.upper(), site, port))
        result = True
    else:
        show_close('Certificate does not use {} as signature algorithm. \
It uses {}. Details={}:{}'.
                   format(alg.upper(), sign_algorith.upper(), site, port))
        result = False
    return result


@track
def is_cert_cn_not_equal_to_site(site, port=PORT):
    """Check whether cert cn is equal to site."""
    result = True
    has_sni = False
    try:
        with __connect(site, port=port) as conn:
            __cert = conn.session.serverCertChain.x509List[0].bytes
            cert = ssl.DER_cert_to_PEM_cert(__cert)
    except socket.error:
        show_unknown('Port closed, Details={}:{}'.format(site, port))
        return False
    except tlslite.errors.TLSRemoteAlert:
        try:
            with __connect_legacy(site, port) as conn:
                __cert = conn.getpeercert(True)
                cert = ssl.DER_cert_to_PEM_cert(__cert)
                has_sni = True
        except socket.error:
            show_unknown('Port closed, Details={}:{}'.
                         format(site, port))
            return False

    cert_obj = load_pem_x509_certificate(cert.encode('utf-8'),
                                         default_backend())
    cert_cn = \
        cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
            0].value

    wc_cert = '*.' + site

    domain = 'NONE'
    if cert_cn.startswith('*.'):
        domain = '.' + cert_cn.split('*.')[1]

    if site != cert_cn and wc_cert != cert_cn and not site.endswith(domain):
        if has_sni:
            show_close('{} CN not equals to site. However server \
supports SNI, Details={}:{}'.format(cert_cn, site, port))
            result = False
        else:
            show_open('{} CN not equals to site, Details={}:{}'.
                      format(cert_cn, site, port))
            result = True
    else:
        show_close('{} CN equals to site, Details={}:{}'.
                   format(cert_cn, site, port))
        result = False
    return result


@track
def is_cert_inactive(site, port=PORT):
    """Check whether cert is still valid."""
    result = True
    try:
        with __connect(site, port=port) as conn:
            __cert = conn.session.serverCertChain.x509List[0].bytes
            cert = ssl.DER_cert_to_PEM_cert(__cert)
    except socket.error:
        show_unknown('Port closed, Details={}:{}'.format(site, port))
        return False
    except tlslite.errors.TLSRemoteAlert:
        try:
            with __connect_legacy(site, port) as conn:
                __cert = conn.getpeercert(True)
                cert = ssl.DER_cert_to_PEM_cert(__cert)
        except socket.error:
            show_unknown('Port closed, Details={}:{}'.
                         format(site, port))
            return False

    cert_obj = load_pem_x509_certificate(cert.encode('utf-8'),
                                         default_backend())

    if cert_obj.not_valid_after > datetime.datetime.now():
        show_close('Certificate is still valid, Details=Not valid \
after: {}, Current time: {}'.format(cert_obj.not_valid_after.isoformat(),
                                    datetime.datetime.now().isoformat()))
        result = False
    else:
        show_open('Certificate is not valid, Details=Not valid \
after: {}, Current time: {}'.format(cert_obj.not_valid_after.isoformat(),
                                    datetime.datetime.now().isoformat()))
        result = True
    return result


@track
def is_cert_validity_lifespan_unsafe(site, port=PORT):
    """Check whether cert lifespan is safe."""
    max_validity_days = 730

    result = True
    try:
        with __connect(site, port=port) as conn:
            __cert = conn.session.serverCertChain.x509List[0].bytes
            cert = ssl.DER_cert_to_PEM_cert(__cert)
    except socket.error:
        show_unknown('Port closed, Details={}:{}'.format(site, port))
        return False
    except tlslite.errors.TLSRemoteAlert:
        try:
            with __connect_legacy(site, port) as conn:
                __cert = conn.getpeercert(True)
                cert = ssl.DER_cert_to_PEM_cert(__cert)
        except socket.error:
            show_unknown('Port closed, Details={}:{}'.
                         format(site, port))
            return False

    cert_obj = load_pem_x509_certificate(cert.encode('utf-8'),
                                         default_backend())

    cert_validity = \
        cert_obj.not_valid_after - cert_obj.not_valid_before

    if cert_validity.days <= max_validity_days:
        show_close('Certificate has a secure lifespan, Details=Not \
valid before: {}, Not valid after: {}'.
                   format(cert_obj.not_valid_before.isoformat(),
                          cert_obj.not_valid_after.isoformat()))
        result = False
    else:
        show_open('Certificate has an insecure lifespan, Details=Not \
valid before: {}, Not valid after: {}'.
                  format(cert_obj.not_valid_before.isoformat(),
                         cert_obj.not_valid_after.isoformat()))
        result = True
    return result


@track
def is_pfs_disabled(site, port=PORT):
    """Check whether PFS is enabled."""
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

    try:
        with __connect(site, port=port,
                       key_exchange_names=['dhe_rsa', 'ecdhe_rsa',
                                           'ecdh_anon', 'dh_anon']):
            show_close('Forward Secrecy enabled on site, Details={}:{}'.
                       format(site, port))
            result = False
    except tlslite.errors.TLSRemoteAlert:
        try:
            with __connect_legacy(site, port, ciphers):
                show_close('Forward Secrecy enabled on site, Details={}:{}'.
                           format(site, port))
                result = False
        except ssl.SSLError:
            show_open('Forward Secrecy not enabled on site, Details={}:{}'.
                      format(site, port))
            return True
    except socket.error:
        show_unknown('Port is closed. Details={}:{}'.
                     format(site, port))
        result = False
    return result


@track
def is_sslv3_enabled(site, port=PORT):
    """Check whether SSLv3 suites are enabled."""
    result = True
    try:
        with __connect(site, port=port, min_version=(3, 0),
                       max_version=(3, 0)):
            show_open('SSLv3 enabled on site, Details={}:{}'.
                      format(site, port))
            result = True
    except tlslite.errors.TLSRemoteAlert:
        show_close('SSLv3 not enabled on site, Details={}:{}'.
                   format(site, port))
        result = False
    except tlslite.errors.TLSAbruptCloseError:
        show_close('SSLv3 not enabled on site, Details={}:{}'.
                   format(site, port))
        result = False
    except tlslite.errors.TLSLocalAlert:
        show_close('SSLv3 not enabled on site, Details={}:{}'.
                   format(site, port))
        result = False
    except socket.error:
        show_unknown('Port is closed for SSLv3 check, Details={}:{}'.
                     format(site, port))
        result = False
    return result


@track
def is_sha1_used(site, port=PORT):
    """Check whether cert use SHA1 in their signature algorithm."""
    return __uses_sign_alg(site, 'sha1', port)


@track
def is_md5_used(site, port=PORT):
    """Check whether cert use MD5 in their signature algorithm."""
    return __uses_sign_alg(site, 'md5', port)


@track
def is_tlsv1_enabled(site, port=PORT):
    """Check whether TLSv1 suites are enabled."""
    result = True
    try:
        with __connect(site, port=port, min_version=(3, 1),
                       max_version=(3, 1)):
            show_open('TLSv1 enabled on site, Details={}:{}'.
                      format(site, port))
            result = True
    except tlslite.errors.TLSRemoteAlert:
        show_close('TLSv1 not enabled on site, Details={}:{}'.
                   format(site, port))
        result = False
    except tlslite.errors.TLSAbruptCloseError:
        show_close('TLSv1 not enabled on site, Details={}:{}'.
                   format(site, port))
        result = False
    except tlslite.errors.TLSLocalAlert:
        show_close('TLSv1 not enabled on site, Details={}:{}'.
                   format(site, port))
        result = False
    except socket.error:
        show_unknown('Port is closed for TLSv1 check, Details={}:{}'.
                     format(site, port))
        result = False
    return result


@track
def has_poodle(site, port=PORT):
    """Check whether POODLE is present."""
    try:
        with __connect(site, port=port, min_version=(3, 0),
                       max_version=(3, 0)) as conn:
            if conn._recordLayer.isCBCMode():  # noqa
                show_open('Site vulnerable to POODLE SSLv3 attack. \
Details={}:{}'.format(site, port))
                return True
            else:
                show_close('Site allows SSLv3. However, it seems not to \
be vulnerable to POODLE SSLv3 attack, Details={}:{}'.format(site, port))
                return False
    except tlslite.errors.TLSRemoteAlert:
        pass
    except tlslite.errors.TLSAbruptCloseError:
        pass
    try:
        with __connect(site, port=port, check_poodle_tls=False):
            pass
    except tlslite.errors.TLSRemoteAlert:
        show_close('Site not vulnerable to POODLE attack. Details={}:{}'.
                   format(site, port))
        return False
    try:
        with __connect(site, port=port, check_poodle_tls=True,
                       cipher_names=["aes256", "aes128", "3des"],
                       min_version=(3, 1)):
            show_open('Site vulnerable to POODLE TLS attack. \
Details={}:{}'.format(site, port))
            return True
    except tlslite.errors.TLSRemoteAlert:
        show_close('Site not vulnerable to POODLE attack. Details={}:{}'.
                   format(site, port))
        return False
    except tlslite.errors.TLSAbruptCloseError:
        show_close('Site not vulnerable to POODLE attack. Details={}:{}'.
                   format(site, port))
        return False


@track
def has_breach(site, port=PORT):
    """Check whether BREACH is present."""

    url = 'https://{}:{}'.format(site, port)
    common_compressors = ['compress', 'exi', 'gzip',
                          'identity', 'pack200-gzip', 'br', 'bzip2',
                          'lzma', 'peerdist', 'sdch', 'xpress', 'xz']

    for compression in common_compressors:
        header = {'Accept-Encoding': '{},deflate'.format(compression)}
        sess = http_helper.HTTPSession(url, headers=header)
        if 'Content-Encoding' in sess.response.headers:
            if compression in sess.response.headers['Content-Encoding']:
                show_open('Site vulnerable to BREACH attack. \
Details={}:{} uses \'{}\' compression'.
                          format(site, port, compression))
                return True
    show_close('Site not vulnerable to BREACH attack. Details={}:{}'.
               format(site, port))
    return False


@track
def allows_anon_ciphers(site, port=PORT):
    """Check whether site accepts anonymous cipher suites."""
    result = True
    try:
        with __connect(site, port=port,
                       anon=True):
            show_open('Site allows anonymous cipher suites, Details={}:{}'.
                      format(site, port))
            result = True
    except tlslite.errors.TLSRemoteAlert:
        show_close('Site not allows anonymous cipher suites, Details={}:{}'.
                   format(site, port))
        result = False
    except tlslite.errors.TLSAbruptCloseError:
        show_close('Site not allows anonymous cipher suites, Details={}:{}'.
                   format(site, port))
        result = False
    except tlslite.errors.TLSLocalAlert:
        show_close('Site not allows anonymous cipher suites, Details={}:{}'.
                   format(site, port))
        result = False
    except socket.error:
        show_unknown('Port is closed, Details={}:{}'.
                     format(site, port))
        result = False
    return result


@track
def allows_weak_ciphers(site, port=PORT):
    """Check whether site accepts weak cipher suites."""
    result = True
    try:
        with __connect(site, port=port,
                       cipher_names=['rc4', '3des']):
            show_open('Site allows weak (RC4 and 3DES) cipher suites, \
Details={}:{}'.format(site, port))
            result = True
    except tlslite.errors.TLSRemoteAlert:
        show_close('Site not allows weak (RC4 and 3DES) cipher suites, \
Details={}:{}'.format(site, port))
        result = False
    except tlslite.errors.TLSAbruptCloseError:
        show_close('Site not allows weak (RC4 and 3DES) cipher suites, \
Details={}:{}'.format(site, port))
        result = False
    except tlslite.errors.TLSLocalAlert:
        show_close('Site not allows weak (RC4 and 3DES) cipher suites, \
Details={}:{}'.format(site, port))
        result = False
    except socket.error:
        show_unknown('Port is closed, Details={}:{}'.
                     format(site, port))
        result = False
    return result


@track
def has_beast(site, port=PORT):
    """Check whether site allows BEAST attack."""
    result = True
    try:
        with __connect(site, port=port, min_version=(3, 1),
                       max_version=(3, 1)) as conn:
            if conn._recordLayer.isCBCMode():  # noqa
                show_open('Site vulnerable to BEAST attack, \
Details={}:{}'.format(site, port))
                result = True
            else:
                show_close('Site allows TLSv1.0. However, it seems not \
to be vulnerable to BEAST attack, Details={}:{}'.format(site, port))
                result = False
    except tlslite.errors.TLSRemoteAlert:
        show_close('Site not vulnerable to BEAST attack, \
Details={}:{}'.format(site, port))
        result = False
    except tlslite.errors.TLSAbruptCloseError:
        show_close('Site not vulnerable to BEAST attack, \
Details={}:{}'.format(site, port))
        result = False
    except tlslite.errors.TLSLocalAlert:
        show_close('Site not vulnerable to BEAST attack, \
Details={}:{}'.format(site, port))
        result = False
    except socket.error:
        show_unknown('Port is closed, Details={}:{}'.
                     format(site, port))
        result = False
    return result
