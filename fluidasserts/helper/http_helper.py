# -*- coding: utf-8 -*-

"""HTTP helper."""

# standard imports
import hashlib
from typing import Optional, Tuple

# 3rd party imports
from urllib.parse import quote as quote


from bs4 import BeautifulSoup
from requests_oauthlib import OAuth1
from requests_ntlm import HttpNtlmAuth
import requests
# pylint: disable=import-error
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# local imports
# None

# pylint: disable=W0212
# pylint: disable=R0902
# pylint: disable=R0913

# pylint: disable=no-member
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class ConnError(Exception):
    """
    A connection error occurred.

    :py:exc:`requests.ConnectionError` wrapper exception.
    """

    pass


class HTTPSession(object):
    """Class of HTTP request objects."""

    def __init__(self, url: str, params: Optional[str] = None,
                 headers: Optional[dict] = None, method: Optional[str] = None,
                 cookies: requests.cookies.RequestsCookieJar = None,
                 data: Optional[str] = '',
                 files: Optional[dict] = None,
                 auth: Optional[Tuple[str, str]] = None,
                 stream: Optional[bool] = False) -> None:
        """
        Construct method.

        :param method: Must be either `PUT` or `DELETE`.
        :param url: URL for the new :class:`HTTPSession` object.
        :param params: Parameters to be sent with the :class:`Request`.
        :param data: Dictionary to be sent in the :class:`Request` body.
        :param headers: Dictionary of HTTP Headers to sent with the Request.
        :param cookies: Dict or CookieJar object to send with the Request.
        :param files: Dictionary of ``'name': file-like-objects``
                      for multipart encoding upload.
        :param auth: Auth tuple to enable Basic/Digest/Custom HTTP Auth.
        :param stream: If ``False``, the response content
                       will be immediately downloaded.
        :return: :class:`HTTPSession` object
        """
        self.url = url
        self.params = params
        self.headers = headers
        self.cookies = cookies
        self.data = data
        self.auth = auth
        self.files = files
        self.method = method
        if self.method:
            assert self.method in ['PUT', 'DELETE']
        self.response = None  # type: requests.Response
        self.is_auth = False
        self.stream = stream
        if self.headers is None:
            self.headers = dict()
        if 'User-Agent' not in self.headers:
            self.headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64; \
rv:45.0) Gecko/20100101 Firefox/45.0'
        if 'Accept' not in self.headers:
            self.headers['Accept'] = '*/*'
        if 'Accept-Language' not in self.headers:
            self.headers['Accept-Language'] = 'en-US,en;q=0.5'

        self.do_request()

    def do_request(self) -> Optional[requests.Response]:  # noqa
        """Do HTTP request."""
        ret = None  # type: ignore
        if self.method in ['PUT', 'DELETE']:
            try:
                if self.method == 'PUT':
                    ret = requests.put(self.url, verify=False,
                                       auth=self.auth,
                                       params=self.params,
                                       cookies=self.cookies,
                                       data=self.data,
                                       headers=self.headers,
                                       timeout=10)
                if self.method == 'DELETE':
                    ret = requests.delete(self.url, verify=False,
                                          auth=self.auth,
                                          params=self.params,
                                          cookies=self.cookies,
                                          data=self.data,
                                          headers=self.headers,
                                          timeout=10)
                self.response = ret
            except (requests.ConnectionError,
                    requests.exceptions.TooManyRedirects) as exc:
                raise ConnError(exc)
        else:
            try:
                if self.data == '':
                    ret = requests.get(self.url, verify=False,
                                       auth=self.auth,
                                       params=self.params,
                                       cookies=self.cookies,
                                       headers=self.headers,
                                       stream=self.stream,
                                       timeout=10)
                else:
                    ret = requests.post(self.url, verify=False,
                                        data=self.data,
                                        auth=self.auth,
                                        params=self.params,
                                        cookies=self.cookies,
                                        headers=self.headers,
                                        files=self.files,
                                        stream=self.stream,
                                        timeout=10)
                self.response = ret
                if self.response.url != self.url:
                    self.url = self.response.url

                if ret.cookies == {}:
                    if (ret.request._cookies != {} and
                            self.cookies != ret.request._cookies):
                        self.cookies = ret.request._cookies
                else:
                    self.cookies = ret.cookies
            except (requests.ConnectionError,
                    requests.exceptions.TooManyRedirects) as exc:
                raise ConnError(exc)
        return ret

    def formauth_by_statuscode(self, code: int) -> requests.Response:
        """
        Authenticate using status code as verification.

        :param code: Integer code of responded HTTP status, e.g. 404 or 500.
        """
        self.headers['Content-Type'] = \
            'application/x-www-form-urlencoded'
        self.headers['Accept'] = '*/*'

        http_req = self.do_request()

        self.is_auth = bool(http_req.status_code == code)

        if http_req.cookies == {}:
            if http_req.request._cookies != {} and \
               self.cookies != http_req.request._cookies:
                self.cookies = http_req.request._cookies
        else:
            self.cookies = http_req.cookies
        self.response = http_req
        self.data = ''
        return http_req

    def formauth_by_response(self, text: str) -> requests.Response:
        """
        Authenticate using regex as verification.

        :param text: Regex to look for in request response.
        """
        self.headers['Content-Type'] = \
            'application/x-www-form-urlencoded'

        http_req = self.do_request()
        if http_req is None:
            return None
        self.is_auth = bool(http_req.text.find(text) >= 0)

        if http_req.cookies == {}:
            if http_req.request._cookies != {} and \
               self.cookies != http_req.request._cookies:
                self.cookies = http_req.request._cookies
        else:
            self.cookies = http_req.cookies
        self.response = http_req
        self.data = ''
        del self.headers['Content-Type']
        return http_req

    def basic_auth(self, user: str, passw: str) -> None:
        """
        Authenticate using BASIC.

        :param user: Username for authentication.
        :param passw: Password for authentication.
        """
        self.__do_auth('BASIC', user, passw)

    def ntlm_auth(self, user: str, passw: str) -> None:
        """
        Authenticate using NTLM.

        :param user: Username for authentication.
        :param passw: Password for authentication.
        """
        self.__do_auth('NTLM', user, passw)

    def oauth_auth(self, user: str, passw: str) -> None:
        """
        Authenticate using OAUTH.

        :param user: Username for authentication.
        :param passw: Password for authentication.
        """
        self.__do_auth('OAUTH', user, passw)

    def __do_auth(self, method: str, user: str, passw: str) -> None:
        """
        Authenticate using HTTP.

        :param user: Username for authentication.
        :param passw: Password for authentication.
        """
        if method == 'BASIC':
            self.auth = (user, passw)
        elif method == 'NTLM':
            self.auth = HttpNtlmAuth(user, passw)
        elif method == 'OAUTH':
            self.auth = OAuth1(user, passw)
        resp = self.do_request()

        self.auth = None
        request_no_auth = self.do_request()
        if request_no_auth.status_code == 401:
            if resp.status_code == 200:
                self.cookies = resp.cookies
                self.response = resp
                self.is_auth = True
            else:
                self.is_auth = False
        else:
            self.is_auth = False

    def get_html_value(self, field_type: str, field_name: str,
                       field: Optional[str] = 'value',
                       enc: Optional[bool] = False) -> str:
        """
        Get a value from an HTML field.

        :param field_type: Name of HTML tag type to look for, e.g. ``script``.
        :param field: Name of field, e.g. ``type``.
        :param enc: Whether to URL-encode the results.
        """
        soup = BeautifulSoup(self.response.text, 'html.parser')
        result_tag = soup.find(field_type,
                               {'name': field_name})
        text_to_get = None
        if result_tag:
            text_to_get = result_tag[field]
        if enc and text_to_get:
            return quote(text_to_get)
        return text_to_get

    def get_fingerprint(self) -> dict:
        """
        Get HTTP fingerprint.

        :return: A dict containing the SHA and banner of the host,
                 as per :meth:`Service.get_fingerprint()`.
        """
        sha256 = hashlib.sha256()
        banner = '\r\n'.join(['{}: {}'.format(x, y)
                              for x, y in self.response.headers.items()])
        sha256.update(banner.encode('utf-8'))
        return dict(sha256=sha256.hexdigest(), banner=banner)
