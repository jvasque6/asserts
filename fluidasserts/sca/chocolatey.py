# -*- coding: utf-8 -*-

"""Software Composition Analysis for Chocolatey packages."""

# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts.helper import sca
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track, level

PACKAGE_MANAGER = 'chocolatey'


@level('high')
@track
def package_has_vulnerabilities(package: str, version: str = None) -> bool:
    """
    Search vulnerabilities on given package/version.

    :param package: Package name.
    :param version: Package version.
    """
    try:
        vulns = sca.get_vulns(PACKAGE_MANAGER, package, version)
        if vulns:
            show_open('Software has vulnerabilities',
                      details=dict(package=package, version=version,
                                   vuln_num=len(vulns), vulns=vulns))
            return True
        show_close('Software doesn\'t have vulnerabilities',
                   details=dict(package=package, version=version))
        return False
    except sca.ConnError as exc:
        show_unknown('Could not connect to SCA provider',
                     details=dict(error=str(exc).replace(':', ',')))
        return False
    except sca.PackageNotFoundException:
        show_unknown('Sofware couldn\'t be found in package manager',
                     details=dict(package=package, version=version))
        return False
