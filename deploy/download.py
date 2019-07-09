"""Download project requirements."""

from requirements_detector import find_requirements
from pip._internal import main as pipmain
import glob

ARCHS = ['x86_64', 'i686', 'armv6l', 'armv7l']
PLATFORMS = ['linux', 'manylinux1', 'win32']
VERSIONS = ['35', '36', '37']
DEST_DIR = 'deploy/installer/packages'
PROJECT_NAME = glob.glob('build/dist/*.zip')[0]


def download(package):
    """Perform a simple pip download."""
    pipmain(['download', '-d', DEST_DIR, package])


def download_specific(package):
    """Perform a platform-specific pip download."""
    for arch in ARCHS:
        for plat in PLATFORMS:
            for version in VERSIONS:
                abis = ['cp34-abi3', 'cp{}m'.format(version),
                        'py{}'.format(version)]
                platform = '{}_{}'.format(plat, arch)
                for abi in abis:
                    pipmain(['download', '-d', DEST_DIR,
                             '--only-binary=:all:', '--platform', platform,
                             '--python-version', version, '--abi', abi,
                             package])


def get_reqs(path):
    """Extract project requirements."""
    _reqs = [(x.name, x.version_specs) for x in find_requirements(path)]
    reqs = []
    for req in _reqs:
        if req[1]:
            reqs.append('{}=={}'.format(req[0], req[1][0][1]))
        else:
            reqs.append('{}'.format(req[0]))
    return reqs

reqs = get_reqs('.')
download('pip')
download('setuptools')
download(PROJECT_NAME)
download_specific(PROJECT_NAME)
for req in reqs:
    download(req)
    download_specific(req)
