# -*- coding: utf-8 -*-

r"""Banner helper.

Usage examples:

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
import hashlib
import re
import socket
import ssl

# 3rd party imports
import certifi

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

    def get_banner(self, server):
        """Get the banner of the service on a given port of an IP address."""
        banner = ''
        try:
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.is_ssl:
                sock = ssl.SSLSocket(sock=raw_socket,
                                     ca_certs=certifi.where(),
                                     cert_reqs=ssl.CERT_REQUIRED,
                                     server_hostname=server)
            else:
                sock = raw_socket
            sock.connect((server, self.port))
            if self.payload is not None:
                sent_bytes = sock.send(self.payload)
                if sent_bytes < len(self.payload):
                    raise socket.error
            banner = sock.recv(5096)
        except socket.error:
            raw_socket = False
            banner = ''
        finally:
            if raw_socket:
                raw_socket.close()

        return banner.rstrip()

    def get_fingerprint(self, server):
        """Get fingerprint of the banner."""
        sha256 = hashlib.sha256()
        banner = self.get_banner(server)
        try:
            sha256.update(banner.encode('utf-8'))
        except AttributeError:
            sha256.update(banner)
        return dict(sha256=sha256.hexdigest(), banner=banner)

    @abstractmethod
    def get_version(self, server):
        """Parse the banner.

        Return the product and version of the service.
        """
        pass


class FTPService(Service):
    """FTP Service definition."""

    def __init__(self, port=21, is_active=False, is_ssl=False,
                 payload=None):
        """Return a new Service object."""
        try:
            super(FTPService, self).__init__(port=port,
                                             is_active=is_active,
                                             is_ssl=is_ssl,
                                             payload=payload)
        except TypeError:
            super().__init__(port=port, is_active=is_active,
                             is_ssl=is_ssl, payload=payload)

    def get_version(self, server):
        """Get version."""
        banner = self.get_banner(server)
        regex_match = re.search(b'220.(.*)', banner)
        version = regex_match.group(1)
        if len(version) < 3:
            return None
        return version


class SMTPService(Service):
    """SMTP Service definition."""

    def __init__(self, port=25, is_active=False, is_ssl=False,
                 payload=None):
        """Return a new Service object."""
        try:
            super(SMTPService, self).__init__(port=port,
                                              is_active=is_active,
                                              is_ssl=is_ssl,
                                              payload=payload)
        except TypeError:
            super().__init__(port=port, is_active=is_active,
                             is_ssl=is_ssl, payload=payload)

    def get_version(self, server):
        """Get version."""
        banner = self.get_banner(server)
        regex_match = re.search(b'220.*ESMTP (.*)', banner)
        if regex_match:
            return regex_match.group(1)
        return None


class HTTPService(Service):
    """HTTP Service definition."""

    def __init__(self, port=80, is_active=True, is_ssl=False,
                 payload=b'HEAD / HTTP/1.0\r\n\r\n'):
        """Return a new Service object."""
        try:
            super(HTTPService, self).__init__(port=port,
                                              is_active=is_active,
                                              is_ssl=is_ssl,
                                              payload=payload)
        except TypeError:
            super().__init__(port=port, is_active=is_active,
                             is_ssl=is_ssl, payload=payload)

    def get_version(self, server):
        """Get version."""
        banner = self.get_banner(server)
        regex_match = re.search(b'Server: [a-z-A-Z]+[^a-zA-Z0-9](.*)',
                                banner)
        if regex_match:
            return regex_match.group(1)
        return None


class HTTPSService(Service):
    """HTTPS Service definition."""

    def __init__(self, port=443, is_active=True, is_ssl=True,
                 payload=b'HEAD / HTTP/1.0\r\n\r\n'):
        """Return a new Service object."""
        try:
            super(HTTPSService, self).__init__(port=port,
                                               is_active=is_active,
                                               is_ssl=is_ssl,
                                               payload=payload)
        except TypeError:
            super().__init__(port=port, is_active=is_active,
                             is_ssl=is_ssl, payload=payload)

    def get_version(self, server):
        """Get version."""
        banner = self.get_banner(server)
        regex_match = re.search(b'Server: [a-z-A-Z]+[^a-zA-Z0-9](.*)',
                                banner)
        if regex_match:
            return regex_match.group(1)
        return None


class SSHService(Service):
    """SSH Service definition."""

    def __init__(self, port=22, is_active=False, is_ssl=False,
                 payload=None):
        """Return a new Service object."""
        try:
            super(SSHService, self).__init__(port=port,
                                             is_active=is_active,
                                             is_ssl=is_ssl,
                                             payload=payload)
        except TypeError:
            super().__init__(port=port, is_active=is_active,
                             is_ssl=is_ssl, payload=payload)

    def get_version(self, server):
        """Get version."""
        banner = self.get_banner(server)
        regex_match = re.search(b'(.*)', banner)
        version = regex_match.group(1)
        if len(version) < 3:
            return None
        return version
