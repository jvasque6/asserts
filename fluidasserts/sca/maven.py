# -*- coding: utf-8 -*-

"""Software Composition Analysis for Maven packages."""

# standard imports
# None

# 3rd party imports
from defusedxml.ElementTree import parse

# local imports
from fluidasserts.helper import sca
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track, level, notify

PACKAGE_MANAGER = 'maven'


def _get_requirements(path: str) -> list:
    """
    Get list of requirements from Maven project.

    Files supported are pom.xml

    :param path: Project path
    """
    reqs = []
    namespaces = {'xmlns': 'http://maven.apache.org/POM/4.0.0'}
    for full_path in sca.full_paths_in_dir(path):
        if not full_path.endswith('pom.xml'):
            continue
        tree = parse(full_path)
        root = tree.getroot()
        deps = root.findall(".//xmlns:dependency",
                            namespaces=namespaces)
        for dep in deps:
            artifact_id = dep.find("xmlns:artifactId",
                                   namespaces=namespaces)
            version = dep.find("xmlns:version", namespaces=namespaces)
            if version is not None:
                if version.text.startswith('$'):
                    reqs.append((artifact_id.text, None))
                else:
                    reqs.append((artifact_id.text, version.text))
            else:
                reqs.append((artifact_id.text, None))
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
        vulns = sca.get_vulns_ossindex(PACKAGE_MANAGER, package, version)
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
    try:
        packages = sca.scan_requirements(reqs, PACKAGE_MANAGER)
    except sca.ConnError as exc:
        show_unknown('Could not connect to SCA provider',
                     details=dict(error=str(exc).replace(':', ',')))
        return False

    if not packages:
        show_unknown('Not packages found in project',
                     details=dict(path=path))
        return False

    result = True
    try:
        proj_vulns = \
            list(filter(lambda x:
                        sca.get_vulns_ossindex(PACKAGE_MANAGER,
                                               x['package'],
                                               x['version']), packages))
    except sca.ConnError as exc:
        show_unknown('Could not connect to SCA provider',
                     details=dict(error=str(exc).replace(':', ',')))
        result = False
    except sca.PackageNotFoundException:
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
