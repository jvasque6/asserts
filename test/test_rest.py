# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.proto.rest."""

# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts.proto import rest


# Constants

MOCK_SERVICE = 'http://localhost:5000'
BASE_URL = MOCK_SERVICE + '/rest'
BWAPP_PORT = 80
NONEXISTANT_SERVICE = 'http://nonexistant.fluidattacks.com'
BAD_FORMAT_SERVICE = 'fluidattacks'

#
# Open tests
#


def test_has_access_open():
    """Resource is available?."""
    assert rest.has_access(BASE_URL + '/access/fail')


def test_content_type_open():
    """Resource is available?."""
    assert rest.accepts_empty_content_type(
        BASE_URL + '/content_type/fail')


def test_insecure_accept_open():
    """Resource is available?."""
    assert rest.accepts_insecure_accept_header(
        BASE_URL + '/insecure_accept/fail')


def test_hsts_open():
    """Header Strict-Transport-Security no establecido?."""
    assert rest.is_header_hsts_missing(
        '%s/hsts/fail' % (BASE_URL))

#
# Closing tests
#


def test_has_access_close():
    """Resource is available?."""
    assert not rest.has_access(BASE_URL + '/access/ok')


def test_content_type_close():
    """Resource is available?."""
    assert not rest.accepts_empty_content_type(
        BASE_URL + '/content_type/ok')
    assert not rest.accepts_empty_content_type(
        NONEXISTANT_SERVICE + '/content_type/ok')


def test_insecure_accept_close():
    """Resource is available?."""
    assert not rest.accepts_insecure_accept_header(
        BASE_URL + '/insecure_accept/ok')
    assert not rest.accepts_insecure_accept_header(
        NONEXISTANT_SERVICE + '/insecure_accept/ok')


def test_hsts_close():
    """Header Strict-Transport-Security establecido?."""
    assert not rest.is_header_hsts_missing(
        '%s/hsts/ok' % (BASE_URL))
    assert not rest.is_header_hsts_missing(
        '%s/hsts/ok' % (NONEXISTANT_SERVICE))
    assert not rest.is_header_hsts_missing(
        '%s/hsts/ok' % (BAD_FORMAT_SERVICE))
