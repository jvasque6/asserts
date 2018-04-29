# -*- coding: utf-8 -*-
"""SSL module."""

# standard imports
from __future__ import absolute_import
import errno
import socket
import ssl
import struct

# 3rd party imports
import tlslite

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track
from fluidasserts.helper import http_helper
from fluidasserts.helper.ssl_helper import connect as connect
from fluidasserts.helper.ssl_helper import connect_legacy as connect_legacy

PORT = 443


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
        with connect(site, port=port,
                     key_exchange_names=['dhe_rsa', 'ecdhe_rsa',
                                         'ecdh_anon', 'dh_anon']):
            show_close('Forward Secrecy enabled on site',
                       details=dict(site=site, port=port))
            result = False
    except tlslite.errors.TLSRemoteAlert:
        try:
            with connect_legacy(site, port, ciphers):
                show_close('Forward Secrecy enabled on site',
                           details=dict(site=site, port=port))
                result = False
        except ssl.SSLError:
            show_open('Forward Secrecy not enabled on site',
                      details=dict(site=site, port=port))
            return True
    except socket.error:
        show_unknown('Port closed', details=dict(site=site, port=port))
        result = False
    return result


@track
def is_sslv3_enabled(site, port=PORT):
    """Check whether SSLv3 suites are enabled."""
    result = True
    try:
        with connect(site, port=port, min_version=(3, 0), max_version=(3, 0)):
            show_open('SSLv3 enabled on site',
                      details=dict(site=site, port=port))
            result = True
    except (tlslite.errors.TLSRemoteAlert, tlslite.errors.TLSAbruptCloseError,
            tlslite.errors.TLSLocalAlert):
        show_close('SSLv3 not enabled on site',
                   details=dict(site=site, port=port))
        result = False
    except socket.error as exception:
        if exception.errno == errno.ECONNRESET:
            show_close('SSLv3 not enabled on site',
                       details=dict(site=site, port=port))
            result = False
        else:
            show_unknown('Port closed', details=dict(site=site, port=port))
            result = False
    return result


@track
def is_tlsv1_enabled(site, port=PORT):
    """Check whether TLSv1 suites are enabled."""
    result = True
    try:
        with connect(site, port=port, min_version=(3, 1), max_version=(3, 1)):
            show_open('TLSv1 enabled on site',
                      details=dict(site=site, port=port))
            result = True
    except (tlslite.errors.TLSRemoteAlert, tlslite.errors.TLSAbruptCloseError,
            tlslite.errors.TLSLocalAlert):
        show_close('TLSv1 not enabled on site',
                   details=dict(site=site, port=port))
        result = False
    except socket.error as exception:
        if exception.errno == errno.ECONNRESET:
            show_close('TLSv1 not enabled on site',
                       details=dict(site=site, port=port))
            result = False
        else:
            show_unknown('Port closed', details=dict(site=site, port=port))
            result = False
    return result


@track
def has_poodle_tls(site, port=PORT):
    """Check whether POODLE TLS is present."""
    result = False
    try:
        with connect(site, port=port, check_poodle_tls=True,
                     cipher_names=["aes256", "aes128", "3des"],
                     min_version=(3, 1)):
            show_open('Site vulnerable to POODLE TLS attack',
                      details=dict(site=site, port=port))
            result = True
    except (tlslite.errors.TLSRemoteAlert, tlslite.errors.TLSAbruptCloseError):
        show_close('Site not vulnerable to POODLE TLS attack',
                   details=dict(site=site, port=port))
        result = False
    except socket.error as exception:
        if exception.errno == errno.ECONNRESET:
            show_close('Site not vulnerable to POODLE TLS attack',
                       details=dict(site=site, port=port))
            result = False
        else:
            show_unknown('Port closed', details=dict(site=site, port=port))
            result = False
    return result


@track
def has_poodle_sslv3(site, port=PORT):
    """Check whether POODLE SSLv3 is present."""
    try:
        with connect(site, port=port, min_version=(3, 0),
                     max_version=(3, 0)) as conn:
            if conn._recordLayer.isCBCMode():  # noqa
                show_open('Site vulnerable to POODLE SSLv3 attack',
                          details=dict(site=site, port=port))
                return True
            show_close('Site allows SSLv3. However, it seems not to \
be vulnerable to POODLE SSLv3 attack',
                       details=dict(site=site, port=port))
            return False
    except (tlslite.errors.TLSRemoteAlert, tlslite.errors.TLSAbruptCloseError):
        pass
    except socket.error as exception:
        if exception.errno == errno.ECONNRESET:
            show_close('Site not vulnerable to POODLE SSLv3 attack',
                       details=dict(site=site, port=port))
            return False
        show_unknown('Port closed', details=dict(site=site, port=port))
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
            fingerprint = sess.get_fingerprint()
            if 'Content-Encoding' in sess.response.headers:
                if compression in sess.response.headers['Content-Encoding']:
                    show_open('Site vulnerable to BREACH attack',
                              details=dict(site=site, port=port,
                                           compression=compression,
                                           fingerprint=fingerprint))
                    return True
        except http_helper.ConnError:
            show_unknown('Could not connect', details=dict(site=site,
                                                           port=port))
            return False
    show_close('Site not vulnerable to BREACH attack',
               details=dict(site=site, port=port))
    return False


@track
def allows_anon_ciphers(site, port=PORT):
    """Check whether site accepts anonymous cipher suites."""
    result = True
    try:
        with connect(site, port=port, anon=True):
            show_open('Site allows anonymous cipher suites',
                      details=dict(site=site, port=port))
            result = True
    except (tlslite.errors.TLSRemoteAlert, tlslite.errors.TLSAbruptCloseError,
            tlslite.errors.TLSLocalAlert):
        show_close('Site not allows anonymous cipher suites',
                   details=dict(site=site, port=port))
        result = False
    except socket.error as exception:
        if exception.errno == errno.ECONNRESET:
            show_close('Site not allows anonymous cipher suites',
                       details=dict(site=site, port=port))
            result = False
        else:
            show_unknown('Port closed', details=dict(site=site, port=port))
            result = False
    return result


@track
def allows_weak_ciphers(site, port=PORT):
    """Check whether site accepts weak cipher suites."""
    result = True
    try:
        with connect(site, port=port,
                     cipher_names=['rc4', '3des', 'null']):
            show_open('Site allows weak (RC4, 3DES and NULL) cipher \
suites', details=dict(site=site, port=port))
            result = True
    except (tlslite.errors.TLSRemoteAlert, tlslite.errors.TLSAbruptCloseError,
            tlslite.errors.TLSLocalAlert):
        show_close('Site not allows weak (RC4, 3DES and NULL) cipher \
suites', details=dict(site=site, port=port))
        result = False
    except socket.error as exception:
        if exception.errno == errno.ECONNRESET:
            show_close('Site not allows weak (RC4, 3DES and NULL) cipher \
suites', details=dict(site=site, port=port))
            result = False
        else:
            show_unknown('Port closed', details=dict(site=site, port=port))
            result = False
    return result


@track
def has_beast(site, port=PORT):
    """Check whether site allows BEAST attack."""
    result = True
    try:
        with connect(site, port=port, min_version=(3, 1),
                     max_version=(3, 1)) as conn:
            if conn._recordLayer.isCBCMode():  # noqa
                show_open('Site enables BEAST attack to clients',
                          details=dict(site=site, port=port))
                result = True
            else:
                show_close('Site allows TLSv1.0. However, it seems \
to be not an enabler to BEAST attack', details=dict(site=site, port=port))
                result = False
    except (tlslite.errors.TLSRemoteAlert, tlslite.errors.TLSAbruptCloseError,
            tlslite.errors.TLSLocalAlert):
        show_close('Site not enables to BEAST attack to clients',
                   details=dict(site=site, port=port))
        result = False
    except socket.error:
        show_unknown('Port closed', details=dict(site=site, port=port))
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
                                      details=dict(site=site, port=port))
                            return True
                        show_close('Site supports SSL/TLS heartbeats, \
but it\'s not vulnerable to Heartbleed.',
                                   details=dict(site=site, port=port))
                        return False
            sock.close()
        show_close("Site doesn't support SSL/TLS heartbeats",
                   details=dict(site=site, port=port))
        return False
    except socket.error:
        show_unknown('Port closed', details=dict(site=site, port=port))
        result = False
    return result
