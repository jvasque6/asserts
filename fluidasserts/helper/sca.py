# -*- coding: utf-8 -*-

"""Software Composition Analysis helper."""

# standard imports
import json
import os
import urllib.parse

# 3rd party imports
from bs4 import BeautifulSoup
from functools import lru_cache
from functools import reduce


# local imports
from fluidasserts.helper import http


class ConnError(http.ConnError):
    """
    A connection error occurred.

    :py:exc:`http.ConnError` wrapper exception.
    """


def _url_encode(string: str) -> str:
    """Return a url encoded string."""
    return urllib.parse.quote(string, safe='')


def _parse_snyk_vulns(html):
    """Parse Snyk HTML content for retrieve vulnerabilities."""
    soup = BeautifulSoup(html, 'html.parser')
    vuln_table = soup.find_all('table',
                               attrs={'class': ['table--comfortable']})
    if not vuln_table:
        return tuple()
    fields = [field.text.strip()
              for field in vuln_table[0].find_all('span',
                                                  attrs={'class':
                                                         ['l-push-left--sm',
                                                          'semver']})]
    return tuple({x: y for x in fields[0::2] for y in fields[1::2]}.items())


def _scantree(path: str):
    """Recursively yield full paths to files for a given directory."""
    for entry in os.scandir(path):
        full_path = entry.path
        if entry.is_dir(follow_symlinks=False):
            yield from _scantree(full_path)
        else:
            yield full_path


@lru_cache(maxsize=None, typed=True)
def full_paths_in_dir(path: str):
    """Return a cacheable tuple of full_paths to files in a dir."""
    return tuple(full_path for full_path in _scantree(path))


def get_vulns_ossindex(package_manager: str, package: str,
                       version: str) -> tuple:
    """
    Search vulnerabilities on given package_manager/package/version.

    :param package_manager: Package manager.
    :param package: Package name.
    :param version: Package version.
    """
    if version:
        url = 'https://ossindex.net/v2.0/package/{}/{}/{}'.format(
            _url_encode(package_manager),
            _url_encode(package),
            _url_encode(version))
    else:
        url = 'https://ossindex.net/v2.0/package/{}/{}'.format(
            _url_encode(package_manager),
            _url_encode(package))
    try:
        sess = http.HTTPSession(url)
        resp = json.loads(sess.response.text)[0]
        vuln_titles = tuple()
        if resp['id'] == 0:
            return vuln_titles
        if int(resp['vulnerability-matches']) > 0:
            vulns = resp['vulnerabilities']
            vuln_titles = tuple([x['title'], ", ".join(x['versions'])]
                                for x in vulns)
            vuln_titles = tuple(reduce(
                lambda l, x: l.append(x) or l if x not in l else l,
                vuln_titles, []))
        return vuln_titles
    except http.ConnError:
        raise ConnError


def get_vulns_snyk(package_manager: str, package: str, version: str) -> tuple:
    """
    Search vulnerabilities on given package_manager/package/version.

    :param package_manager: Package manager.
    :param package: Package name.
    :param version: Package version.
    """
    if version:
        url = 'https://snyk.io/vuln/{}:{}@{}'.format(
            _url_encode(package_manager),
            _url_encode(package),
            _url_encode(version))
    else:
        url = 'https://snyk.io/vuln/{}:{}'.format(
            _url_encode(package_manager),
            _url_encode(package))
    try:
        sess = http.HTTPSession(url, timeout=20)
        return _parse_snyk_vulns(sess.response.text)
    except http.ConnError:
        raise ConnError
