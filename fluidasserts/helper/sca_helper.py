# -*- coding: utf-8 -*-

"""Software Composition Analysis for Python packages."""

# standard imports
# None

# 3rd party imports
import json

# local imports
from fluidasserts.helper import http_helper


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
    except http_helper.ConnError:
        raise

    return json.loads(sess.response.text)[0]
