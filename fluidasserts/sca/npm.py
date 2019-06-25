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


def _get_all_versions(json_obj: dict) -> None:
    """Return all dependencies and requirements in the given json_obj."""
    deps = []
    if isinstance(json_obj, dict):
        # In a package.json
        #    'dependencies': {
        #        '$dep': '$version'
        #        ...
        #    }

        # In a package-lock.json
        #    'dependencies': {
        #        '$dep': {
        #            'version': '$version',
        #            'requires': {
        #                 'req': '$version'
        #                 ...
        #                 ...it may be nested from this point on
        #            }
        #        }
        #        ...
        #    }

        for dep, metadata in json_obj.get('dependencies', {}).items():
            if isinstance(metadata, str):
                deps.append((dep, metadata))
            elif isinstance(metadata, dict):
                if 'version' in metadata:
                    deps.append((dep, metadata['version']))
                if 'requires' in metadata and \
                        isinstance(metadata['requires'], dict):
                    for req, version in metadata['requires'].items():
                        deps.append((req, version))
                deps.extend(_get_all_versions(metadata))
    return deps


def _get_requirements(path: str) -> set:
    """
    Get a list of requirements from NPM project.

    Files supported are package.json and package-lock.json

    :param path: Project path
    """
    reqs = set()
    dictionary = {c: None for c in '^~<=>'}
    for path in sca.full_paths_in_dir(path):
        is_package = path.endswith('package.json')
        is_package_lock = path.endswith('package-lock.json')
        if is_package or is_package_lock:
            with open(path) as file:
                data = json.load(file)
            reqs.update(
                (path, dep.replace('@types/', ''), ver.translate(dictionary))
                for dep, ver in _get_all_versions(data))
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
        has_vulns = None
        proj_vulns = {}
        reqs = _get_requirements(path)
        if not reqs:
            show_unknown('Not packages found in project',
                         details=dict(path=path))
            return False
        for full_path, dep, ver in reqs:
            _vulns = sca.get_vulns_snyk(PACKAGE_MANAGER, dep, ver)
            if _vulns:
                has_vulns = True
                try:
                    proj_vulns[full_path][f'{dep} {ver}'] = _vulns
                except KeyError:
                    proj_vulns[full_path] = {f'{dep} {ver}': _vulns}
    except sca.ConnError as exc:
        show_unknown('Could not connect to SCA provider',
                     details=dict(error=str(exc).replace(':', ',')))
        return False
    except FileNotFoundError:
        show_unknown('Project dir not found',
                     details=dict(path=path))
        return False
    if has_vulns:
        show_open('Project has dependencies with vulnerabilities',
                  details=dict(project_path=path,
                               vulnerabilities=proj_vulns))
        return True
    show_close('Project has not dependencies with vulnerabilities',
               details=dict(project_path=path))
    return False
