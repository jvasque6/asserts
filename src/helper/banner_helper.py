# -*- coding: utf-8 -*-

r"""
Modulo para verificacion de banners de diferentes protocolos.

Ejemplo de uso:

ftp_service = FTPService()
ssh_service = SSHService()
telnet_service = TELNETService()
smtp_service = SMTPService()
http_service = HTTPService(payload='GET / HTTP/1.0\r\n\r\n')
https_service = HTTPSService(payload='GET / HTTP/1.0\r\n\r\n')

banner = get_banner(https_service, 'fluid.la')
version = get_version(https_service, banner)
print version
"""


# standard imports
from abc import ABCMeta
from abc import abstractmethod
import re
import socket
import ssl

# 3rd party imports
# none

# local imports
# none

# pylint: disable=R0204
# pylint: disable=R0903


class Service(object):
    """Abstract class of service."""

    __metaclass__ = ABCMeta

    def __init__(self, port, is_active, is_ssl, payload=None):
        """Return a new Service object."""
        self.port = port
        self.is_active = is_active
        self.is_ssl = is_ssl
        self.payload = payload

    @abstractmethod
    def get_version(self, banner):
        """Function get_version.

        Parse the banner and return the product and version of
        the service.
        """
        pass


class FTPService(Service):
    """FTP Service definition."""

    def __init__(self, port=21, is_active=False, is_ssl=False,
                 payload=None):
        """Return a new Service object."""
        try:
            super(self.__class__, self).__init__(port=port,
                                                 is_active=is_active,
                                                 is_ssl=is_ssl,
                                                 payload=payload)
        except:
            super().__init__(port=port, is_active=is_active,
                             is_ssl=is_ssl, payload=payload)

    def get_version(self, banner):
        """Get version."""
        regex_match = re.search(b'220.(.*)', banner)
        version = regex_match.group(1)
        if len(version) < 3:
            return None
        return version


class SSHService(Service):
    """SSH Service definition."""

    def __init__(self, port=22, is_active=False, is_ssl=False,
                 payload=None):
        """Return a new Service object."""
        try:
            super(self.__class__, self).__init__(port=port,
                                                 is_active=is_active,
                                                 is_ssl=is_ssl,
                                                 payload=payload)
        except:
            super().__init__(port=port, is_active=is_active,
                             is_ssl=is_ssl, payload=payload)

    def get_version(self, banner):
        """Get version."""
        return banner


class TELNETService(Service):
    """TELNET Service definition."""

    def __init__(self, port=23, is_active=False, is_ssl=False,
                 payload=None):
        """Return a new Service object."""
        try:
            super(self.__class__, self).__init__(port=port,
                                                 is_active=is_active,
                                                 is_ssl=is_ssl,
                                                 payload=payload)
        except:
            super().__init__(port=port, is_active=is_active,
                             is_ssl=is_ssl, payload=payload)

    def get_version(self, banner):
        """Get version."""
        return banner


class SMTPService(Service):
    """SMTP Service definition."""

    def __init__(self, port=25, is_active=False, is_ssl=False,
                 payload=None):
        """Return a new Service object."""
        try:
            super(self.__class__, self).__init__(port=port,
                                                 is_active=is_active,
                                                 is_ssl=is_ssl,
                                                 payload=payload)
        except:
            super().__init__(port=port, is_active=is_active,
                             is_ssl=is_ssl, payload=payload)

    def get_version(self, banner):
        """Get version."""
        # pylint: disable=W1401
        regex_match = re.search(b'220 (\S+) (.*ESMTP.*)', banner)
        if regex_match:
            return regex_match.group(2)
        return None


class HTTPService(Service):
    """HTTP Service definition."""

    def __init__(self, port=80, is_active=True, is_ssl=False,
                 payload=b'GET / HTTP/1.0\r\n\r\n'):
        """Return a new Service object."""
        try:
            super(self.__class__, self).__init__(port=port,
                                                 is_active=is_active,
                                                 is_ssl=is_ssl,
                                                 payload=payload)
        except:
            super().__init__(port=port, is_active=is_active,
                             is_ssl=is_ssl, payload=payload)

    def get_version(self, banner):
        """Get version."""
        regex_match = re.search(b'Server: [a-z-A-Z]+[^a-zA-Z0-9](.*)',
                                banner)
        if regex_match:
            return regex_match.group(1)
        return None


class HTTPSService(Service):
    """HTTPS Service definition."""

    def __init__(self, port=443, is_active=True, is_ssl=True,
                 payload=b'GET / HTTP/1.0\r\n\r\n'):
        """Return a new Service object."""
        try:
            super(self.__class__, self).__init__(port=port,
                                                 is_active=is_active,
                                                 is_ssl=is_ssl,
                                                 payload=payload)
        except:
            super().__init__(port=port, is_active=is_active,
                             is_ssl=is_ssl, payload=payload)

    def get_version(self, banner):
        """Get version."""
        regex_match = re.search(b'Server: [a-z-A-Z]+[^a-zA-Z0-9](.*)',
                                banner)
        if regex_match:
            return regex_match.group(1)
        return None


def service_connect(server, port, is_ssl, payload=None):
    """Get the banner of the service on a given port of an IP address."""
    banner = ''
    try:
        raw_socket = socket.create_connection((server, port))
        if is_ssl:
            sock = ssl.wrap_socket(raw_socket)
        else:
            sock = raw_socket
        if payload is not None:
            sent_bytes = sock.send(payload)
            if sent_bytes < len(payload):
                raise socket.error
        banner = sock.recv(5096)
    except socket.error:
        banner = ''
    finally:
        sock.close()

    return banner


def get_banner(service, server, port=None):
    """High level method to get banner."""
    if port is None:
        port = service.port

    banner = service_connect(server, port,
                             service.is_ssl,
                             service.payload)
    return banner.rstrip()


def get_version(service, banner):
    """High level method to get version."""
    return service.get_version(banner)
