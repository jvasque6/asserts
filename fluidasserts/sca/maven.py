# -*- coding: utf-8 -*-

"""Software Composition Analysis for Maven packages."""

# standard imports
import os

# 3rd party imports
from xml.etree import ElementTree

# local imports
from fluidasserts.helper import sca_helper
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track, level

PACKAGE_MANAGER = 'maven'


def _get_requirements(path: str) -> list:
    """
    Get list of requirements from Maven project.

    Files supported are pom.xml

    :param path: Project path
    """
    reqs = []
    namespaces = {'xmlns': 'http://maven.apache.org/POM/4.0.0'}
    for root, _, files in os.walk(path):
        for pom_file in files:
            if pom_file != 'pom.xml':
                continue
            full_path = os.path.join(root, pom_file)
            tree = ElementTree.parse(full_path)
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


@level('high')
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


@level('high')
@track
def project_has_vulnerabilities(path: str) -> bool:
    """
    Search vulnerabilities on given project directory.

    :param path: Project path.
    """
    try:
        reqs = _get_requirements(path)
        response = sca_helper.scan_requirements(reqs, PACKAGE_MANAGER)
    except sca_helper.ConnError as exc:
        show_unknown('Could not connect to SCA provider',
                     details=dict(error=str(exc).replace(':', ',')))
        return False

    if not response:
        show_unknown('Not packages found in project',
                     details=dict(path=path))
        return False

    result = False
    for package in response:
        if package['version'] == -1:
            continue
        ret = package_has_vulnerabilities(package['package'],
                                          package['version'])
        if ret:
            result = True
    return result
