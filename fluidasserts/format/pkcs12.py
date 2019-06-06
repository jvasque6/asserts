# -*- coding: utf-8 -*-

"""This module allows to check ``PKCS12`` vulnerabilities."""


# standard imports
from os.path import isfile

# 3rd party imports
from OpenSSL import crypto

# local imports
from fluidasserts import show_open
from fluidasserts import show_close
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track, level, notify


@notify
@level('high')
@track
def has_no_password_protection(p12_file: str) -> bool:
    """
    Check if a .p12 file is password protected.

    :param p12_file: .p12 file to check
    """
    if not isfile(p12_file):
        show_unknown('File not found',
                     details=dict(file=p12_file))
        return False
    try:
        crypto.load_pkcs12(open(p12_file, 'rb').read())
        show_open('File is not password protected',
                  details=dict(file=p12_file))
        return True
    except crypto.Error:
        show_close('File is password protected',
                   details=dict(file=p12_file))
        return False
