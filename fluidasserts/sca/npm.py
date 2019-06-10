# -*- coding: utf-8 -*-

"""Software Composition Analysis for NodeJS packages."""

# standard imports
import json

# 3rd party imports
# None

# local imports
from fluidasserts.helper import sca
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track, level, notify

PACKAGE_MANAGER = 'npm'


def _get_requirements(path: str) -> list:
    """
    Get list of requirements from NPM project.

    Files supported are package.json

    :param path: Project path
    """
    reqs = []
    for full_path in sca.full_paths_in_dir(path):
        if not full_path.endswith('package.json'):
            continue
        with open(full_path) as json_file:
            json_data = json_file.read()
        data = json.loads(json_data)
        try:
            deps = data['dependencies']
        except KeyError:
            continue
        else:
            reqs += [(dep.replace('@types/', ''),
                      ver.translate({ord(c): None for c in '^~<=>'}))
                     for dep, ver in deps.items()]
    return reqs


@notify
@level('high')
@track
def package_has_vulnerabilities(package: str, version: str = None) -> bool:
    """
    Search vulnerabilities on given package/version.

    :param package: Package name.
    :param version: Package version.
    """
    try:
        vulns = sca.get_vulns_snyk(PACKAGE_MANAGER, package, version)
        if vulns:
            show_open('Software has vulnerabilities',
                      details=dict(package=package, version=version,
                                   vuln_num=len(vulns),
                                   vulns=vulns))
            return True
        show_close('Software doesn\'t have vulnerabilities',
                   details=dict(package=package, version=version))
        return False
    except sca.ConnError as exc:
        show_unknown('Could not connect to SCA provider',
                     details=dict(error=str(exc).replace(':', ',')))
        return False


@notify
@level('high')
@track
def project_has_vulnerabilities(path: str) -> bool:
    """
    Search vulnerabilities on given project directory.

    :param path: Project path.
    """
    try:
        reqs = _get_requirements(path)
    except FileNotFoundError:
        show_unknown('Project dir not found',
                     details=dict(path=path))
        return False

    if not reqs:
        show_unknown('Not packages found in project',
                     details=dict(path=path))
        return False

    result = True
    try:
        unfiltered = {x[0]: sca.get_vulns_snyk(PACKAGE_MANAGER, x[0], x[1])
                      for x in reqs}
        proj_vulns = {k: v for k, v in unfiltered.items() if v}
    except sca.ConnError as exc:
        show_unknown('Could not connect to SCA provider',
                     details=dict(error=str(exc).replace(':', ',')))
        result = False
    else:
        if proj_vulns:
            show_open('Project has dependencies with vulnerabilities',
                      details=dict(project_path=path,
                                   vulnerabilities=proj_vulns))
            result = True
        else:
            show_close('Project has not dependencies with vulnerabilities',
                       details=dict(project_path=path))
            result = False
    return result
