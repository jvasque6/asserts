# -*- coding: utf-8 -*-

"""Modulo para verificación del protocolo FTP.

Este modulo permite verificar vulnerabilidades propias de FTP como:

    * Transporte de información de forma plana,
    * Conexión al servicio de forma anonima.
    * Servicio FTP activado
"""

# standard imports
import logging

# 3rd party imports
from ftplib import error_perm
from ftplib import FTP_TLS

# local imports
from fluidasserts import tcp


def __auth(ip, port, username, password):
    try:
        ftp = FTP_TLS.connect(ip, port)
        ftp.login(username, password)
        ftp.quit()
        logging.info('FTP Authentication %s, Details=%s, %s',
                     ip, username + ":" + password, "OPEN")
    except error_perm:
        logging.info('FTP Authentication %s, Details=%s, %s',
                     ip, username + ":" + password, "CLOSE")


def login(ip, username, password):
    __auth(ip, username, password)


def supports_anonymous_connection(ip, port=21):
    __auth(ip, port, "anonymous", "anonymous")


def is_open(ip, port=21):
    tcp.openport(ip, port)
