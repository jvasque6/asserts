# -*- coding: utf-8 -*-

"""REST module."""

# standard imports
# None

# third party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track
from fluidasserts.helper import http_helper


@track
def has_access(url, *args, **kwargs):
    """Check if a bad text is present."""
    http_session = http_helper.HTTPSession(url, *args, **kwargs)
    ok_access_list = [200]
    if http_session.response.status_code in ok_access_list:
        show_open('Access available to {}'.format(url))
        return True
    show_close('Access not available to {}'.format(url))
    return False


@track
def accepts_empty_content_type(url, *args, **kwargs):
    """Check if given URL accepts empty Content-Type requests."""
    if 'headers' in kwargs:
        assert 'Content-Type' not in kwargs['headers']
    expected_codes = [406, 415]
    error_codes = [400, 401, 403, 404, 500]
    session = http_helper.HTTPSession(url, *args, **kwargs)

    if session.response.status_code in error_codes:
        show_unknown('URL {} returned error'.format(url),
                     details=dict(error=session.response.status_code))
        return True
    if session.response.status_code not in expected_codes:
        show_open('URL {} accepts empty Content-Type requests'.
                  format(url))
        return True
    show_close('URL {} rejects empty Content-Type requests'.
               format(url))
    return False


@track
def accepts_insecure_accept_header(url, *args, **kwargs):
    """Check if given URL accepts insecure Accept request header value."""
    expected_codes = [406, 415]
    error_codes = [400, 401, 403, 404, 500]
    if 'headers' in kwargs:
        kwargs['headers'].update({'Accept': '*/*'})
    else:
        kwargs = {'headers': {'Accept': '*/*'}}
    session = http_helper.HTTPSession(url, *args, **kwargs)

    if session.response.status_code in error_codes:
        show_unknown('URL {} returned error'.format(url),
                     details=dict(http_code=session.response.status_code))
        return True
    if session.response.status_code not in expected_codes:
        show_open('URL {} accepts insecure Accept request header value'.
                  format(url))
        return True
    show_close('URL {} rejects insecure Accept request header value'.
               format(url))
    return False
