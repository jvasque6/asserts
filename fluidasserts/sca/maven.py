# -*- coding: utf-8 -*-

"""Software Composition Analysis for Maven packages."""

# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts.helper.http_helper import ConnError
from fluidasserts.helper import sca_helper
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track


@track
def has_vulnerabilities(package: str, version: str = None) -> bool:
    """
    Search vulnerabilities on given package/version.

    :param package: Package name.
    :param version: Package version.
    """
    try:
        resp = sca_helper.get_vulns('maven', package, version)
    except ConnError as exc:
        show_unknown('Could not connect to SCA provider',
                     details=dict(error=str(exc).replace(':', ',')))
        return False
    if resp['id'] == 0:
        show_unknown('Sofware couldn\'t be found in package manager',
                     details=dict(package=package, version=version))
        return False
    v_matches = resp['vulnerability-matches']
    if int(v_matches) > 0:
        vulns = resp['vulnerabilities']
        vuln_titles = [x['title'] for x in vulns]
        show_open('Software has vulnerabilities',
                  details=dict(package=package, version=version,
                               vuln_num=v_matches, vulns=vuln_titles))
        return True
    show_close('Software doesn\'t have vulnerabilities',
               details=dict(package=package, version=version))
    return False
