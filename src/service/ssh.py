# -*- coding: utf-8 -*-
"""SSH module."""

# standard imports
from __future__ import absolute_import
import socket

# 3rd party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.helper import banner_helper
from fluidasserts.utils.decorators import track

PORT = 22

def __not_in(alg_list, algo):
    """Function to check algorithm list"""
    for algth in alg_list:
        if algo == algth:
            return False
    return True

@track
def is_cbc_used(site, port=PORT):
    """Function to check whether ssh has CBC algorithms enabled"""
    result = True
    try:
        service = banner_helper.SSHService(port)
        fingerprint = service.get_fingerprint(site)
        conn = socket.create_connection((site, port), 5)
        conn.send('SSH-2.0-OpenSSH_6.0p1\r\n')
        version = conn.recv(50).split('\n')[0]
        version = version+"do nothing"
        ciphers = conn.recv(984)
        conn.close()

        if "-cbc" not in ciphers:
            all_c = ciphers.split(',')
            cipher_text = ""
            for cipher in all_c:
                cipher_text = cipher_text+cipher+","
            show_close('SSH does not have insecure CBC encription algorithms',
                       details=dict(site=site, cipher_text=cipher_text,
                                    fingerprint=fingerprint))
            result = False
        else:
            all_c = ciphers.split(',')
            cbc = ""
            algos = []
            for ciph in all_c:
                if "-cbc" in ciph:
                    if __not_in(algos, ciph):
                        algos.append(ciph)
                        cbc = cbc+ciph+", "
            show_open('SSH has insecure CBC encription algorithms',
                      details=dict(site=site, cbc=cbc,
                                   fingerprint=fingerprint))
            result = True

        return result
    except socket.timeout:
        show_unknown('Port closed', details=dict(site=site, port=port))
        return False

@track
def is_hmac_used(site, port=PORT):
    """Function to check whether ssh has weak hmac algorithms enabled"""
    result = True
    try:
        service = banner_helper.SSHService(port)
        fingerprint = service.get_fingerprint(site)
        conn = socket.create_connection((site, port), 5)
        version = conn.recv(50).split('\n')[0]
        version = version+"do nothing"
        conn.send('SSH-2.0-OpenSSH_6.0p1\r\n')
        ciphers = conn.recv(984)
        conn.close()

        if "hmac-" not in ciphers:
            all_c = ciphers.split(',')
            cipher_text = ""
            for cipher in all_c:
                cipher_text = cipher_text+cipher+","
            show_close('SSH does not have insecure HMAC encription algorithms',
                       details=dict(site=site, cipher_text=cipher_text,
                                    fingerprint=fingerprint))
            result = False
        else:

            all_c = ciphers.split(',')
            hmac = ""
            algos = []
            for cipher in all_c:
                if "hmac-md5" in cipher or "hmac-sha1" in cipher:
                    if __not_in(algos, cipher):
                        algos.append(cipher)
                        hmac = hmac + cipher +", "
            show_open('SSH has insecure HMAC encription algorithms',
                      details=dict(site=site, hmac=hmac,
                                   fingerprint=fingerprint))
            result = True

        return result
    except socket.timeout:
        show_unknown('Port closed', details=dict(site=site, port=port))
        return False
