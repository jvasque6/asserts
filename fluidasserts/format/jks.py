# -*- coding: utf-8 -*-

"""This module allows to check ``JKS`` vulnerabilities."""


# standard imports
import os

# 3rd party imports
import jks

# local imports
from fluidasserts import show_open
from fluidasserts import show_close
from fluidasserts import show_unknown
from fluidasserts.utils.generic import get_sha256
from fluidasserts.utils.generic import full_paths_in_dir
from fluidasserts.utils.decorators import track, level, notify


@notify
@level('high')
@track
def has_no_password_protection(path: str) -> bool:
    """
    Check if .jks files are password protected.

    :param path: path to check
    """
    if not os.path.exists(path):
        show_unknown('Path does not exist',
                     details=dict(path=path))
        return False
    jks_with_password: list = []
    jks_without_password: list = []
    for full_path in full_paths_in_dir(path):
        if not full_path.endswith('.jks'):
            continue
        try:
            jks.KeyStore.load(full_path, '')
        except jks.util.KeystoreSignatureException:
            # has password
            jks_with_password.append(dict(path=full_path,
                                          sha256=get_sha256(full_path)))
        else:
            # has not password
            jks_without_password.append(dict(path=full_path,
                                             sha256=get_sha256(full_path)))
    if jks_without_password:
        show_open('JKS is/are not password protected',
                  details=dict(jks_without_password=jks_without_password))
        return True
    show_close('JKS is/are password protected',
               details=dict(jks_with_password=jks_with_password))
    return False
