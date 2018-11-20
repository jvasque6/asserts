# -*- coding: utf-8 -*-

"""This module allows to check SIP vulnerabilities."""

# standard imports
import base64
import email
import io
import re
import socket

# third party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.helper import http
from fluidasserts.utils.decorators import track, level


def _make_udp_request(server: str, port: int, data: str):
    """Make UDP request to SIP server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    while data:
        bytes_sent = sock.sendto(data[:8192].encode(), (server, port))
        data = data[bytes_sent:]
    buff, _ = sock.recvfrom(8192)
    return buff.decode()


def _make_tcp_request(server: str, port: int, data: str):
    """Make TCP request to SIP server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((server, port))
    sock.send(data.encode())
    buff = sock.recv(8192)
    return buff.decode()


@level('low')
@track
def is_version_visible(server: str, port: int = 5060,
                       source_ip: str = '127.0.0.1',
                       source_port: int = 5060) -> bool:
    """
    Check if SIP server version is visible.

    :param ipaddress: IP address to test.
    :param port: Port to connect to.
    """
    request = """OPTIONS sip:100@{dest_ip} SIP/2.0
Via: SIP/2.0/UDP {source_ip}:{source_port};rport
Content-Length: 0
From: "fake" <sip:fake@{source_ip}>
Accept: application/sdp
User-Agent: Fluid Asserts
To: <sip:100@1.1.1.1>
Contact: sip:fake@{source_ip}:{source_port}
CSeq: 1 OPTIONS
Call-ID: fake-id@{source_ip}
Max-Forwards: 70

"""
    request = request.format(source_ip=source_ip, source_port=source_port,
                             dest_ip=server, dest_port=port)
    request = request.replace('\n', '\r\n')

    proto = None
    try:
        recv_data = _make_udp_request(server, port, request)
        proto = 'UDP'
    except socket.error:
        try:
            recv_data = _make_tcp_request(server, port, request)
            proto = 'TCP'
        except socket.error as exc:
            show_unknown('Could not connect',
                         details=dict(server=server, port=port, proto=proto,
                                      error=str(exc).replace(':', ',')))
            return False
    _, headers_alone = recv_data.split('\r\n', 1)
    message = email.message_from_file(io.StringIO(headers_alone))
    headers = dict(message.items())
    if 'Server' not in headers or 'User-Agent' not in headers:
        show_close('Server or User-Agent header were not returned',
                   details=dict(server=server, port=port, proto=proto))
        return False
    regex_match = re.search(r'([a-z-A-Z]+)[^a-zA-Z0-9](.*)',
                            headers['Server'])
    if regex_match:
        show_open('SIP server version visible',
                  details=dict(server=server, port=port, proto=proto,
                               product=regex_match.group(1),
                               version=regex_match.group(2)))
        result = True
    else:
        show_close('SIP server version not visible',
                   details=dict(server=server, port=port, proto=proto))
        result = False
    return result


@level('high')
@track
def unify_phone_has_default_credentials(hostname: str,
                                        password: str = '123456') -> bool:
    """
    Check if Unify OpenScape Desk Phone IP 55G has default credentials.

    :param hostname: IP or host of phone.
    :param password: Default password.
    """
    url = 'https://{}/index.cmd?user=Admin'.format(hostname)
    sess = http.HTTPSession(url)

    sess.data = 'page_submit=WEBMp_Admin_Login&lang=es&AdminPassword={}'\
        .format(password)
    sess.url = 'https://{}/page.cmd'.format(hostname)
    sess.do_request()

    failed = "action='./page.cmd'"

    if failed not in sess.response.text:
        show_open('Phone has default credentials',
                  details=dict(host=hostname, username='Admin',
                               password=password))
        result = True
    else:
        show_close('Phone has not default credentials',
                   details=dict(host=hostname, username='Admin',
                                password=password))
        result = False
    return result


@level('high')
@track
def polycom_phone_has_default_credentials(hostname: str,
                                          password: str = '456') -> bool:
    """
    Check if Polycom SoundStation IP 6000 has default credentials.

    :param hostname: IP or host of phone.
    :param password: Default password.
    """
    url = 'https://{}/login.htm'.format(hostname)
    sess = http.HTTPSession(url)

    creds = 'Polycom:{}'.format(password)
    encoded = base64.b64encode(creds.encode())

    sess.headers.update({'X-Requested-With': 'XMLHttpRequest'})
    sess.headers.update({'Authorization': 'Basic {}'.format(encoded.decode())})
    sess.url = 'https://{}/auth.htm?t=Tue,%2020%20Nov%202018%2019:48:43%20GMT'\
        .format(hostname)
    sess.do_request()

    expected = "SoundStation IP 6000"

    if expected in sess.response.text:
        show_open('Phone has default credentials',
                  details=dict(host=hostname, username='Admin',
                               password=password))
        result = True
    else:
        show_close('Phone has not default credentials',
                   details=dict(host=hostname, username='Admin',
                                password=password))
        result = False
    return result
