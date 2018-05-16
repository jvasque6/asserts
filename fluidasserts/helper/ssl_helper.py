# -*- coding: utf-8 -*-
"""SSL module."""

# standard imports
from __future__ import absolute_import
from contextlib import contextmanager
import copy
import socket
import ssl

# 3rd party imports
import certifi
import tlslite

# local imports
# None

PORT = 443

ORIG_METHOD = copy.deepcopy(tlslite.recordlayer.RecordLayer.addPadding)
CIPHER_NAMES = ["chacha20-poly1305",
                "aes256gcm", "aes128gcm",
                "aes256", "aes128"]
KEY_EXCHANGE = ["rsa", "dhe_rsa", "ecdhe_rsa", "srp_sha", "srp_sha_rsa",
                "ecdh_anon", "dh_anon"]


def _my_add_padding(self, data):
    """Add padding to data so that it is multiple of block size."""
    current_length = len(data)
    block_length = self.blockSize
    padding_length = block_length - 1 - (current_length % block_length)
    padding_bytes = bytearray([padding_length] * (padding_length + 1))
    padding_bytes = bytearray(x ^ 42 for x in padding_bytes[0:-1])
    padding_bytes.append(padding_length)
    data += padding_bytes
    return data


@contextmanager
def connect_legacy(hostname, port=PORT, ciphers=None):
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
def connect(hostname, port=PORT, check_poodle_tls=False, min_version=(3, 1),
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
        tlslite.recordlayer.RecordLayer.addPadding = _my_add_padding
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
