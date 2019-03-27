# -*- coding: utf-8 -*-

"""Software Composition Analysis helper."""

# standard imports
import re

# 3rd party imports
import json
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


def get_vulns_vulners(package: str, version: str) -> bool:
    """
    Search vulnerabilities on given package_manager/package/version.

    :param package_manager: Package manager.
    :param package: Package name.
    :param version: Package version.
    """
    base_url = 'https://vulners.com/api/v3/search/lucene/?query='
    if version:
        query = \
            'affectedSoftware.name%3A{}%20AND%20affectedSoftware.\
version%3A%22{}%22'.format(package, version)
    else:
        query = 'affectedSoftware.name%3A{}'.format(package)
    url = base_url + query

    try:
        sess = http.HTTPSession(url)
        resp = json.loads(sess.response.text)
        if resp['data']['total'] == 0:
            return []
        vulns = resp['data']['search']
        if version:
            vuln_titles = \
                [[x['flatDescription'], x['_id'],
                  ", ".join(x['highlight']['affectedSoftware.version'])]
                 for x in vulns]
        else:
            vuln_titles = [[x['flatDescription'], x['_id']] for x in vulns]
        vuln_titles = reduce(lambda l, x: l.append(x) or
                             l if x not in l else l, vuln_titles, [])
        return vuln_titles
    except http.ConnError:
        raise ConnError


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


def get_vulns_synk(package_manager: str, package: str, version: str) -> bool:
    """
    Search vulnerabilities on given package_manager/package/version.

    :param package_manager: Package manager.
    :param package: Package name.
    :param version: Package version.
    """
    base_url = 'https://snyk.io'
    url = base_url + '/vuln/{}:{}'.format(package_manager, package)

    try:
        sess = http.HTTPSession(url, timeout=20)
        vulns_re = re.search('embedded = ([^;]+)', sess.response.text)
        vulns_raw = vulns_re.groups()[0]
        vulns_json = json.loads(vulns_raw)

        if not vulns_json:
            return []
        vulns = vulns_json['packageVersions']
        if version:
            vuln_titles = {x['version']: x['severityList']
                           for x in vulns if x['hasVuln'] and
                           x['version'] == version}
        else:
            vuln_titles = {x['version']: x['severityList']
                           for x in vulns if x['hasVuln']}

        return vuln_titles
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
