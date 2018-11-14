# -*- coding: utf-8 -*-

"""Archivo estandar para generacion de instalador.

Este modulo define los parametros minimos requeridos para generar
un instalador estandar de fluidasserts.
"""
import time
import io
from setuptools import setup


def _get_readme():
    """Returns fluidasserts readme."""
    readme_path = 'conf/README.rst'
    with io.open(readme_path, 'rt', encoding='utf8') as readme_f:
        return readme_f.read()


def _get_version():
    """Returns fluidasserts version."""
    cur_time = time.localtime()
    min_month = (cur_time.tm_mday - 1) * 1440 + cur_time.tm_hour * 60 + \
        cur_time.tm_min
    return time.strftime('%y.%m.{}').format(min_month)


setup(
    name='fluidasserts',
    description='Assertion Library for Security Assumptions',
    long_description=_get_readme(),
    version=_get_version(),
    url='https://fluidattacks.com/web/en/products/asserts',
    project_urls={'Documentation': 'https://fluidsignal.gitlab.io/asserts/'},
    package_data={'': ['conf/conf.cfg', 'conf/conf.spec']},
    author='Fluid Attacks Engineering Team',
    author_email='engineering@fluidattacks.com',
    packages=[
        'fluidasserts',
        'fluidasserts.format',
        'fluidasserts.helper',
        'fluidasserts.syst',
        'fluidasserts.proto',
        'fluidasserts.lang',
        'fluidasserts.utils',
        'fluidasserts.sca',
        'fluidasserts.cloud',
        'fluidasserts.cloud.aws',
        'fluidasserts.db',
    ],
    data_files=[
        ('', ['conf/conf.cfg', 'conf/conf.spec']),
        ],
    package_dir={
        'fluidasserts': 'fluidasserts',
    },
    classifiers=[
        'Environment :: Console',
        'Topic :: Security',
        'Topic :: Software Development :: Testing',
        'Topic :: Software Development :: Quality Assurance',
        'Development Status :: 5 - Production/Stable',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: Other/Proprietary License',
    ],
    install_requires=[
        'configobj==5.0.6',          # fluidasserts
        'PyPDF2==1.26.0',            # fluidasserts.format.pdf
        'requests==2.20.1',          # fluidasserts.proto.http
        'certifi==2018.10.15',       # fluidasserts.proto.ssl
        'ldap3==2.5.1',              # fluidasserts.proto.ldap
        'paramiko==2.4.2',           # fluidasserts.helper.ssh_helper
        'pywinrm==0.3.0',            # fluidasserts.helper.winrm_helper
        'beautifulsoup4==4.6.3',     # fluidasserts.helper.http_helper
        'dnspython==1.15.0',         # fluidasserts.proto.dns
        'tlslite-ng==0.7.5',         # fluidasserts.proto.ssl
        'pyOpenSSL==18.0.0',         # fluidasserts.proto.ssl
        'colorama==0.4.0',           # logging
        'pysmb==1.1.25',             # fluidasserts.proto.smb
        'mixpanel==4.3.2',           # fluidasserts.utils.decorators
        'pytesseract==0.2.5',        # fluidasserts.format.captcha
        'pillow==5.3.0',             # fluidasserts.format.captcha
        'pyparsing==2.3.0',          # fluidasserts.lang
        'oyaml==0.7',                # fluidasserts
        'pygments==2.2.0',           # fluidasserts
        'viewstate==0.4.3',          # fluidasserts.proto.http
        'ntplib==0.3.3',             # fluidasserts.proto.http
        'pytz==2018.7',              # fluidasserts.proto.http
        'requirements-detector==0.6',  # fluidasserts.sca
        'defusedxml==0.5.0',         # fluidasserts.sca
        'boto3==1.9.40',             # fluidasserts.cloud.aws
        'python-dateutil==2.7.5',    # fluidasserts.cloud.aws
        'mysql-connector==2.1.6',    # fluidasserts.db.mysql_db
        'pycrypto==2.6.1; platform_system == "Linux"',
    ],
    include_package_data=True,      # archivos a incluir en MANIFEST.in
    entry_points={
            'console_scripts': ['asserts=fluidasserts.utils.cli:main'],
        },
)
