# -*- coding: utf-8 -*-
"""SSL module."""

# standard imports
from __future__ import absolute_import
from contextlib import contextmanager
import copy
import datetime
import socket
import ssl
import struct

# 3rd party imports
import certifi
import tlslite
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
CIPHER_NAMES = ["chacha20-poly1305",
                "aes256gcm", "aes128gcm",
                "aes256", "aes128"]
KEY_EXCHANGE = ["rsa", "dhe_rsa", "ecdhe_rsa", "srp_sha", "srp_sha_rsa",
                "ecdh_anon", "dh_anon"]

ORIG_METHOD = copy.deepcopy(tlslite.recordlayer.RecordLayer.addPadding)


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


def __hex2bin(arr):
    return ''.join('{:02x}'.format(x) for x in arr).decode('hex')


def __rcv_tls_record(sock):
    try:
        tls_header = sock.recv(5)
        if not tls_header:
            return None, None, None
        if len(tls_header) < 5:
            return None, None, None
        typ, ver, length = struct.unpack('>BHH', tls_header)
        message = ''
        while len(message) != length:
            message += sock.recv(length-len(message))
        if not message:
            return None, None, None
        return typ, ver, message
    except socket.error:
        return None, None, None


def __build_client_hello(tls_ver):
    ssl_version_mapping = {
        'SSLv3':   0x00,
        'TLSv1.0': 0x01,
        'TLSv1.1': 0x02,
        'TLSv1.2': 0x03
    }
    client_hello = [
        # TLS header ( 5 bytes)
        0x16,               # Content type (0x16 for handshake)
        0x03, ssl_version_mapping[tls_ver],         # TLS Version
        0x00, 0xdc,         # Length
        # Handshake header
        0x01,               # Type (0x01 for ClientHello)
        0x00, 0x00, 0xd8,   # Length
        0x03, ssl_version_mapping[tls_ver],         # TLS Version
        # Random (32 byte)
        0x53, 0x43, 0x5b, 0x90, 0x9d, 0x9b, 0x72, 0x0b,
        0xbc, 0x0c, 0xbc, 0x2b, 0x92, 0xa8, 0x48, 0x97,
        0xcf, 0xbd, 0x39, 0x04, 0xcc, 0x16, 0x0a, 0x85,
        0x03, 0x90, 0x9f, 0x77, 0x04, 0x33, 0xd4, 0xde,
        0x00,               # Session ID length
        0x00, 0x66,         # Cipher suites length
        # Cipher suites (51 suites)
        0xc0, 0x14, 0xc0, 0x0a, 0xc0, 0x22, 0xc0, 0x21,
        0x00, 0x39, 0x00, 0x38, 0x00, 0x88, 0x00, 0x87,
        0xc0, 0x0f, 0xc0, 0x05, 0x00, 0x35, 0x00, 0x84,
        0xc0, 0x12, 0xc0, 0x08, 0xc0, 0x1c, 0xc0, 0x1b,
        0x00, 0x16, 0x00, 0x13, 0xc0, 0x0d, 0xc0, 0x03,
        0x00, 0x0a, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x1f,
        0xc0, 0x1e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x9a,
        0x00, 0x99, 0x00, 0x45, 0x00, 0x44, 0xc0, 0x0e,
        0xc0, 0x04, 0x00, 0x2f, 0x00, 0x96, 0x00, 0x41,
        0xc0, 0x11, 0xc0, 0x07, 0xc0, 0x0c, 0xc0, 0x02,
        0x00, 0x05, 0x00, 0x04, 0x00, 0x15, 0x00, 0x12,
        0x00, 0x09, 0x00, 0x14, 0x00, 0x11, 0x00, 0x08,
        0x00, 0x06, 0x00, 0x03, 0x00, 0xff,
        0x01,               # Compression methods length
        0x00,               # Compression method (0x00 for NULL)
        0x00, 0x49,         # Extensions length
        # Extension: ec_point_formats
        0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,
        # Extension: elliptic_curves
        0x00, 0x0a, 0x00, 0x34, 0x00, 0x32, 0x00, 0x0e,
        0x00, 0x0d, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x0c,
        0x00, 0x18, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x16,
        0x00, 0x17, 0x00, 0x08, 0x00, 0x06, 0x00, 0x07,
        0x00, 0x14, 0x00, 0x15, 0x00, 0x04, 0x00, 0x05,
        0x00, 0x12, 0x00, 0x13, 0x00, 0x01, 0x00, 0x02,
        0x00, 0x03, 0x00, 0x0f, 0x00, 0x10, 0x00, 0x11,
        # Extension: SessionTicket TLS
        0x00, 0x23, 0x00, 0x00,
        # Extension: Heartbeat
        0x00, 0x0f, 0x00, 0x01, 0x01]
    return client_hello


def __build_heartbeat(tls_ver):
    ssl_version_mapping = {
        'SSLv3':   0x00,
        'TLSv1.0': 0x01,
        'TLSv1.1': 0x02,
        'TLSv1.2': 0x03
    }

    heartbeat = [
        0x18,       # Content Type (Heartbeat)
        0x03, ssl_version_mapping[tls_ver],  # TLS version
        0x00, 0x03,  # Length
        # Payload
        0x01,       # Type (Request)
        0x40, 0x00  # Payload length
    ]
    return heartbeat


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

    if check_poodle_tls:
        tlslite.recordlayer.RecordLayer.addPadding = __my_add_padding
    else:
        tlslite.recordlayer.RecordLayer.addPadding = ORIG_METHOD

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


def __uses_sign_alg(site, alg, port):
    """Check whether cert use a hash method in their signature."""
    result = True

    try:
        with __connect(site, port=port) as connection:
            __cert = connection.session.serverCertChain.x509List[0].bytes
            cert = ssl.DER_cert_to_PEM_cert(__cert)
    except socket.error:
        show_unknown('Port closed', details='Site="{}:{}"'.
                     format(site, port))
        return False
    except tlslite.errors.TLSRemoteAlert:
        try:
            with __connect_legacy(site, port) as conn:
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
        with __connect(site, port=port) as conn:
            __cert = conn.session.serverCertChain.x509List[0].bytes
            cert = ssl.DER_cert_to_PEM_cert(__cert)
    except socket.error:
        show_unknown('Port closed', details='Site="{}:{}"'.
                     format(site, port))
        return False
    except tlslite.errors.TLSRemoteAlert:
        try:
            with __connect_legacy(site, port) as conn:
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
            0].value

    wc_cert = '*.' + site

    domain = 'NONE'
    if cert_cn.startswith('*.'):
        domain = '.' + cert_cn.split('*.')[1]

    if site != cert_cn and wc_cert != cert_cn and not site.endswith(domain):
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
        with __connect(site, port=port) as conn:
            __cert = conn.session.serverCertChain.x509List[0].bytes
            cert = ssl.DER_cert_to_PEM_cert(__cert)
    except socket.error:
        show_unknown('Port closed', details='Site="{}:{}"'.
                     format(site, port))
        return False
    except tlslite.errors.TLSRemoteAlert:
        try:
            with __connect_legacy(site, port) as conn:
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
        with __connect(site, port=port) as conn:
            __cert = conn.session.serverCertChain.x509List[0].bytes
            cert = ssl.DER_cert_to_PEM_cert(__cert)
    except socket.error:
        show_unknown('Port closed', details='Site="{}:{}"'.
                     format(site, port))
        return False
    except tlslite.errors.TLSRemoteAlert:
        try:
            with __connect_legacy(site, port) as conn:
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
            show_close('Forward Secrecy enabled on site',
                       details='Site="{}:{}"'.format(site, port))
            result = False
    except tlslite.errors.TLSRemoteAlert:
        try:
            with __connect_legacy(site, port, ciphers):
                show_close('Forward Secrecy enabled on site',
                           details='Site="{}:{}"'.format(site, port))
                result = False
        except ssl.SSLError:
            show_open('Forward Secrecy not enabled on site',
                      details='Site="{}:{}"'.format(site, port))
            return True
    except socket.error:
        show_unknown('Port closed', details='Site="{}:{}"'.
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
            show_open('SSLv3 enabled on site',
                      details='Site="{}:{}"'.format(site, port))
            result = True
    except tlslite.errors.TLSRemoteAlert:
        show_close('SSLv3 not enabled on site',
                   details='Site="{}:{}"'.format(site, port))
        result = False
    except tlslite.errors.TLSAbruptCloseError:
        show_close('SSLv3 not enabled on site',
                   details='Site="{}:{}"'.format(site, port))
        result = False
    except tlslite.errors.TLSLocalAlert:
        show_close('SSLv3 not enabled on site',
                   details='Site="{}:{}"'.format(site, port))
        result = False
    except socket.error:
        show_unknown('Port closed', details='Site="{}:{}"'.
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
            show_open('TLSv1 enabled on site',
                      details='Site="{}:{}"'.format(site, port))
            result = True
    except tlslite.errors.TLSRemoteAlert:
        show_close('TLSv1 not enabled on site',
                   details='Site="{}:{}"'.format(site, port))
        result = False
    except tlslite.errors.TLSAbruptCloseError:
        show_close('TLSv1 not enabled on site',
                   details='Site="{}:{}"'.format(site, port))
        result = False
    except tlslite.errors.TLSLocalAlert:
        show_close('TLSv1 not enabled on site',
                   details='Site="{}:{}"'.format(site, port))
        result = False
    except socket.error:
        show_unknown('Port closed', details='Site="{}:{}"'.
                     format(site, port))
        result = False
    return result


@track
def has_poodle_tls(site, port=PORT):
    """Check whether POODLE TLS is present."""
    result = False
    try:
        with __connect(site, port=port, check_poodle_tls=True,
                       cipher_names=["aes256", "aes128", "3des"],
                       min_version=(3, 1)):
            show_open('Site vulnerable to POODLE TLS attack',
                      details='Site="{}:{}"'.format(site, port))
            result = True
    except tlslite.errors.TLSRemoteAlert:
        show_close('Site not vulnerable to POODLE TLS attack',
                   details='Site="{}:{}"'.format(site, port))
        result = False
    except tlslite.errors.TLSAbruptCloseError:
        show_close('Site not vulnerable to POODLE TLS attack',
                   details='Site="{}:{}"'.format(site, port))
        result = False
    except socket.error:
        show_unknown('Port closed', details='Site="{}:{}"'.
                     format(site, port))
        return False
    return result


@track
def has_poodle_sslv3(site, port=PORT):
    """Check whether POODLE SSLv3 is present."""
    try:
        with __connect(site, port=port, min_version=(3, 0),
                       max_version=(3, 0)) as conn:
            if conn._recordLayer.isCBCMode():  # noqa
                show_open('Site vulnerable to POODLE SSLv3 attack',
                          details='Site="{}:{}"'.format(site, port))
                return True
            show_close('Site allows SSLv3. However, it seems not to \
be vulnerable to POODLE SSLv3 attack',
                       details='Site="{}:{}"'.format(site, port))
            return False
    except tlslite.errors.TLSRemoteAlert:
        pass
    except tlslite.errors.TLSAbruptCloseError:
        pass
    except socket.error:
        show_unknown('Port closed', details='Site="{}:{}"'.
                     format(site, port))
        return False
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
        try:
            sess = http_helper.HTTPSession(url, headers=header)
            if 'Content-Encoding' in sess.response.headers:
                if compression in sess.response.headers['Content-Encoding']:
                    show_open('Site vulnerable to BREACH attack',
                              details='Site="{}:{}" uses "{}" compression'.
                              format(site, port, compression))
                    return True
        except http_helper.ConnError:
            show_unknown('Could not connect', details='Site="{}:{}"'.
                         format(site, port))
            return False
    show_close('Site not vulnerable to BREACH attack',
               details='Site="{}:{}"'.format(site, port))
    return False


@track
def allows_anon_ciphers(site, port=PORT):
    """Check whether site accepts anonymous cipher suites."""
    result = True
    try:
        with __connect(site, port=port,
                       anon=True):
            show_open('Site allows anonymous cipher suites',
                      details='Site="{}:{}"'.format(site, port))
            result = True
    except tlslite.errors.TLSRemoteAlert:
        show_close('Site not allows anonymous cipher suites',
                   details='Site="{}:{}"'.format(site, port))
        result = False
    except tlslite.errors.TLSAbruptCloseError:
        show_close('Site not allows anonymous cipher suites',
                   details='Site="{}:{}"'.format(site, port))
        result = False
    except tlslite.errors.TLSLocalAlert:
        show_close('Site not allows anonymous cipher suites',
                   details='Site="{}:{}"'.format(site, port))
        result = False
    except socket.error:
        show_unknown('Port closed', details='Site="{}:{}"'.
                     format(site, port))
        result = False
    return result


@track
def allows_weak_ciphers(site, port=PORT):
    """Check whether site accepts weak cipher suites."""
    result = True
    try:
        with __connect(site, port=port,
                       cipher_names=['rc4', '3des', 'null']):
            show_open('Site allows weak (RC4, 3DES and NULL) cipher \
suites', details='Site="{}:{}"'.format(site, port))
            result = True
    except tlslite.errors.TLSRemoteAlert:
        show_close('Site not allows weak (RC4, 3DES and NULL) cipher \
suites', details='Site="{}:{}"'.format(site, port))
        result = False
    except tlslite.errors.TLSAbruptCloseError:
        show_close('Site not allows weak (RC4, 3DES and NULL) cipher \
suites', details='Site="{}:{}"'.format(site, port))
        result = False
    except tlslite.errors.TLSLocalAlert:
        show_close('Site not allows weak (RC4, 3DES and NULL) cipher \
suites', details='Site="{}:{}"'.format(site, port))
        result = False
    except socket.error:
        show_unknown('Port closed', details='Site="{}:{}"'.
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
                show_open('Site enables BEAST attack to clients',
                          details='Site="{}:{}"'.format(site, port))
                result = True
            else:
                show_close('Site allows TLSv1.0. However, it seems \
to be not an enabler to BEAST attack', details='Site="{}:{}"'.
                           format(site, port))
                result = False
    except tlslite.errors.TLSRemoteAlert:
        show_close('Site not enables to BEAST attack to clients',
                   details='Site="{}:{}"'.format(site, port))
        result = False
    except tlslite.errors.TLSAbruptCloseError:
        show_close('Site not enables to BEAST attack to clients',
                   details='Site="{}:{}"'.format(site, port))
        result = False
    except tlslite.errors.TLSLocalAlert:
        show_close('Site not enables to BEAST attack to clients',
                   details='Site="{}:{}"'.format(site, port))
        result = False
    except socket.error:
        show_unknown('Port closed', details='Site="{}:{}"'.
                     format(site, port))
        result = False
    return result


@track
def has_heartbleed(site, port=PORT):
    """Check whether site allows HEARTBLEED attack."""
    # pylint: disable=too-many-nested-blocks
    try:
        versions = ['TLSv1.2', 'TLSv1.1', 'TLSv1.0', 'SSLv3']
        for vers in versions:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((site, port))
            sock.send(__hex2bin(__build_client_hello(vers)))
            typ, _, _ = __rcv_tls_record(sock)
            if not typ:
                continue
            if typ == 22:
                # Received Server Hello
                sock.send(__hex2bin(__build_heartbeat(vers)))
                while True:
                    typ, _, pay = __rcv_tls_record(sock)
                    if typ == 21 or typ is None:
                        break
                    if typ == 24:
                        # Received hearbeat response
                        if len(pay) > 3:
                            # Length is higher than sent
                            show_open('Site vulnerable to Heartbleed \
attack ({})'.format(vers),
                                      details='Site="{}:{}"'.
                                      format(site, port))
                            return True
                        show_close('Site supports SSL/TLS heartbeats, \
but it\'s not vulnerable to Heartbleed.',
                                   details='Site="{}:{}"'.
                                   format(site, port))
                        return False
            sock.close()
        show_close('Site doesn\'t support SSL/TLS heartbeats',
                   details='Site="{}:{}"'.format(site, port))
        return False
    except socket.error:
        show_unknown('Port closed', details='Site="{}:{}"'.
                     format(site, port))
        result = False
    return result
