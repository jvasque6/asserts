# -*- coding: utf-8 -*-

"""Software Composition Analysis helper."""

# standard imports
# None

# 3rd party imports
import json

# local imports
from fluidasserts.helper import http_helper


class ConnError(http_helper.ConnError):
    """
    A connection error occurred.

    :py:exc:`http_helper.ConnError` wrapper exception.
    """

    pass


class PackageNotFoundException(Exception):
    """
    A connection error occurred.

    :py:exc:`Exception` wrapper exception.
    """

    pass


def get_vulns(package_manager: str, package: str, version: str) -> bool:
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
        sess = http_helper.HTTPSession(url)
        resp = json.loads(sess.response.text)[0]
        if resp['id'] == 0:
            raise PackageNotFoundException
        if int(resp['vulnerability-matches']) > 0:
            vulns = resp['vulnerabilities']
            vuln_titles = [x['title'] for x in vulns]
        else:
            vuln_titles = []
        return vuln_titles
    except http_helper.ConnError:
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
            vulns = get_vulns(package_manager, req[0], req[1])
        except PackageNotFoundException:
            result.append(dict(package=req[0], version=-1, vulns=[]))
        except http_helper.ConnError:
            raise ConnError
        result.append(dict(package=req[0], version=req[1], vulns=vulns))
    return result
