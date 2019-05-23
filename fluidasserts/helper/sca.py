# -*- coding: utf-8 -*-

"""Software Composition Analysis helper."""

# standard imports
import json

# 3rd party imports
from bs4 import BeautifulSoup
from functools import reduce

# local imports
from fluidasserts.helper import http


class ConnError(http.ConnError):
    """
    A connection error occurred.

    :py:exc:`http.ConnError` wrapper exception.
    """


class PackageNotFoundException(Exception):
    """
    A connection error occurred.

    :py:exc:`Exception` wrapper exception.
    """


def _parse_snyk_vulns(html):
    """Parse Snyk HTML content for retrieve vulnerabilities."""
    soup = BeautifulSoup(html, 'html.parser')
    vuln_table = soup.find_all('table',
                               attrs={'class': ['table--comfortable']})
    if not vuln_table:
        return {}
    fields = [field.text.strip()
              for field in vuln_table[0].find_all('span',
                                                  attrs={'class':
                                                         ['l-push-left--sm',
                                                          'semver']})]
    return {x: y for x in fields[0::2] for y in fields[1::2]}


def get_vulns_ossindex(package_manager: str, package: str,
                       version: str) -> bool:
    """
    Search vulnerabilities on given package_manager/package/version.

    :param package_manager: Package manager.
    :param package: Package name.
    :param version: Package version.
    """
    base_url = 'https://ossindex.net/v2.0/package'
    if version:
        url = base_url + '/' + package_manager + '/' + package + '/' + version
    else:
        url = base_url + '/' + package_manager + '/' + package

    try:
        sess = http.HTTPSession(url)
        resp = json.loads(sess.response.text)[0]
        if resp['id'] == 0:
            raise PackageNotFoundException
        if int(resp['vulnerability-matches']) > 0:
            vulns = resp['vulnerabilities']
            vuln_titles = [[x['title'], ", ".join(x['versions'])]
                           for x in vulns]
            vuln_titles = reduce(lambda l, x: l.append(x) or
                                 l if x not in l else l, vuln_titles, [])
        else:
            vuln_titles = []
        return vuln_titles
    except http.ConnError:
        raise ConnError


def get_vulns_snyk(package_manager: str, package: str, version: str) -> bool:
    """
    Search vulnerabilities on given package_manager/package/version.

    :param package_manager: Package manager.
    :param package: Package name.
    :param version: Package version.
    """
    base_url = 'https://snyk.io'
    if version:
        url = base_url + '/vuln/{}:{}@{}'.format(package_manager,
                                                 package, version)
    else:
        url = base_url + '/vuln/{}:{}'.format(package_manager, package)
    try:
        sess = http.HTTPSession(url, timeout=20)
        vuln_names = _parse_snyk_vulns(sess.response.text)

        if not vuln_names:
            return []
        return vuln_names
    except http.ConnError:
        raise ConnError


def scan_requirements(requirements: list, package_manager: str) -> list:
    """
    Search vulnerabilities on given project directory.

    :param package_manager: Package manager.
    :param requirements: Requirement list.
    """
    result = []
    for req in requirements:
        try:
            vulns = get_vulns_ossindex(package_manager, req[0], req[1])
            result.append(dict(package=req[0], version=req[1], vulns=vulns))
        except PackageNotFoundException:
            result.append(dict(package=req[0], version=-1, vulns=[]))
        except http.ConnError:
            raise ConnError
    return result
