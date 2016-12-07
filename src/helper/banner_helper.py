# -*- coding: utf-8 -*-

"""
Modulo para verificación de banners de diferentes protocolos.

Ejemplo de uso:

ftp_service = FTPService()
ssh_service = SSHService()
telnet_service = TELNETService()
smtp_service = SMTPService()
http_service = HTTPService(payload='GET / HTTP/1.0\r\n\r\n')
https_service = HTTPSService(payload='GET / HTTP/1.0\r\n\r\n')

banner = get_banner(http_service, 'google.com')
version = get_version(http_service, banner)
print version
"""


# standard imports
from abc import ABCMeta, abstractmethod
import socket
import re

# 3rd party imports
# none

# local imports
# none


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
        """
        This method should parse the banner and return the product
        and version of the service.
        """
        pass


class FTPService(Service):
    """FTP Service definition."""

    def __init__(self, port=21, is_active=False, is_ssl=False,
                 payload=None):
        """Return a new Service object."""
        self.port = port
        self.is_active = is_active
        self.is_ssl = is_ssl
        self.payload = payload

    def get_version(self, banner):
        """Get version."""
        m = re.search(r'220.(.*)', banner)
        return m.group(1)


class SSHService(Service):
    """SSH Service definition."""

    def __init__(self, port=22, is_active=False, is_ssl=False,
                 payload=None):
        """Return a new Service object."""
        self.port = port
        self.is_active = is_active
        self.is_ssl = is_ssl
        self.payload = payload

    def get_version(self, banner):
        """Get version."""
        return banner


class TELNETService(Service):
    """TELNET Service definition."""

    def __init__(self, port=23, is_active=False, is_ssl=False,
                 payload=None):
        """Return a new Service object."""
        self.port = port
        self.is_active = is_active
        self.is_ssl = is_ssl
        self.payload = payload

    def get_version(self, banner):
        """Get version."""
        return banner


class SMTPService(Service):
    """SMTP Service definition."""

    def __init__(self, port=25, is_active=False, is_ssl=False,
                 payload=None):
        """Return a new Service object."""
        self.port = port
        self.is_active = is_active
        self.is_ssl = is_ssl
        self.payload = payload

    def get_version(self, banner):
        """Get version."""
        m = re.search(r'220 (\S+) (.*ESMTP.*)', banner)
        return m.group(2)


class HTTPService(Service):
    """HTTP Service definition."""

    def __init__(self, port=80, is_active=True, is_ssl=False,
                 payload=None):
        """Return a new Service object."""
        self.port = port
        self.is_active = is_active
        self.is_ssl = is_ssl
        self.payload = payload

    def get_version(self, banner):
        """Get version."""
        m = re.search(r'Server: (.*)', banner)
        return m.group(1)


class HTTPSService(Service):
    """HTTPS Service definition."""

    def __init__(self, port=443, is_active=True, is_ssl=True,
                 payload=None):
        """Return a new Service object."""
        self.port = port
        self.is_active = is_active
        self.is_ssl = is_ssl
        self.payload = payload

    def get_version(self, banner):
        """Get version."""
        m = re.search(r'Server: (.*)', banner)
        return m.group(1)


def passive_service_connect(server, port):
    """
    Gets the banner of the service on a given port of an IP address
    """
    banner = ""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server, port))
        banner = sock.recv(5096)
    except socket.error:
        banner = ""
    finally:
        sock.close()

    return banner


def active_service_connect(server, port, payload):
    """
    Gets the banner of the service on a given port of an IP address
    """
    banner = ""
    try:
        sock = socket.create_connection((server, port))
        sent_bytes = sock.send(payload)
        if sent_bytes < len(payload):
            raise socket.error
        banner = sock.recv(5096)
    except socket.error:
        banner = ""
    finally:
        sock.close()

    return banner


def get_banner(service, server, port=None):
    if service.is_active:
        banner = active_service_connect(server,
                                        service.port,
                                        service.payload)
    else:
        banner = passive_service_connect(server,
                                         service.port)
    return banner


def get_version(service, banner):
    return service.get_version(banner)
