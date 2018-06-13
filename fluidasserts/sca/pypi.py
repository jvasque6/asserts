# -*- coding: utf-8 -*-

"""Software Composition Analysis for Python packages."""

# standard imports
# None

# 3rd party imports
from requirements_detector import find_requirements
from requirements_detector.detect import RequirementsNotFound

# local imports
from fluidasserts.helper import sca_helper
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track

PACKAGE_MANAGER = 'pypi'


def _get_requirements(path: str) -> list:
    """
    Get list of requirements from Python project.

    Files supported are setup.py and requierements.txt

    :param path: Project path
    """
    _reqs = [(x.name, x.version_specs) for x in find_requirements(path)]
    reqs = []
    for req in _reqs:
        if req[1]:
            reqs.append((req[0], req[1][0][1]))
        else:
            reqs.append((req[0], None))
    return reqs


@track
def package_has_vulnerabilities(package: str, version: str = None) -> bool:
    """
    Search vulnerabilities on given package/version.

    :param package: Package name.
    :param version: Package version.
    """
    try:
        vulns = sca_helper.get_vulns(PACKAGE_MANAGER, package, version)
        if vulns:
            show_open('Software has vulnerabilities',
                      details=dict(package=package, version=version,
                                   vuln_num=len(vulns), vulns=vulns))
            return True
        show_close('Software doesn\'t have vulnerabilities',
                   details=dict(package=package, version=version))
        return False
    except sca_helper.ConnError as exc:
        show_unknown('Could not connect to SCA provider',
                     details=dict(error=str(exc).replace(':', ',')))
        return False
    except sca_helper.PackageNotFoundException:
        show_unknown('Sofware couldn\'t be found in package manager',
                     details=dict(package=package, version=version))
        return False


@track
def project_has_vulnerabilities(path: str) -> bool:
    """
    Search vulnerabilities on given project directory.

    :param path: Project path.
    """
    result = False
    try:
        reqs = _get_requirements(path)
        response = sca_helper.scan_requirements(reqs, PACKAGE_MANAGER)
    except sca_helper.ConnError as exc:
        show_unknown('Could not connect to SCA provider',
                     details=dict(error=str(exc).replace(':', ',')))
        return False
    except (FileNotFoundError, RequirementsNotFound):
        show_unknown('Could not find requierements',
                     details=dict(path=path))
        return False

    for package in response:
        if package['version'] == -1:
            show_unknown('Sofware couldn\'t be found in package manager',
                         details=dict(package=package['package']))
            continue
        if package['vulns']:
            result = True
            show_open('Software has vulnerabilities',
                      details=dict(package=package['package'],
                                   version=package['version'],
                                   vuln_num=len(package['vulns']),
                                   vulns=package['vulns']))
        else:
            show_close('Software doesn\'t have vulnerabilities',
                       details=dict(package=package['package'],
                                    version=package['version']))
    return result
