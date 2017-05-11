# -*- coding: utf-8 -*-

"""Archivo estandar para generacion de instalador.

Este modulo define los parametros minimos requeridos para generar
un instalador estandar de FLUIDAsserts.
"""

from setuptools import setup, find_packages
import time

setup(
    name='FLUIDAsserts',
    description='Assertion Library for Security Assumptions',
    version=time.strftime('0.%Y%m%d.%H%M'),
    url='https://fluid.la/',
    package_data={'': ['conf/conf.cfg', 'conf/conf.spec']},
    author='FLUID Engineering Team',
    author_email='engineering@fluid.la',
    packages=[
        'fluidasserts',
        'fluidasserts.format',
        'fluidasserts.helper',
        'fluidasserts.system',
        'fluidasserts.service',
    ],
    data_files=[
        ('', ['conf/conf.cfg', 'conf/conf.spec']),
        ],
    package_dir={
        'fluidasserts': 'src',
    },
    classifiers=[
        'Environment :: Console',
        'Topic :: Security',
        'Topic :: Software Development :: Testing',
        'Topic :: Software Development :: Quality Assurance',
        'Development Status :: 2 - Pre-Alpha',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
    ],
    install_requires=[
        'configobj==5.0.6',          # src
        'PyPDF2==1.26.0',            # src.pdf
        'requests==2.13.0',          # src.http
        'requests-oauthlib==0.8.0',  # src.http
        'cryptography==1.8.1',       # src.http_ssl
        'certifi==2017.1.23',        # src.http_ssl
        'ldap3==2.2.2',              # src.ldap
        'paramiko==2.1.2',           # src.ssh_helper
        'pywinrm==0.2.2',            # src.winrm_helper
        'beautifulsoup4==4.5.3',     # src.html
        'dnspython==1.15.0',         # src.dns
        'tlslite-ng==0.7.0-alpha3',  # src.http_ssl
        'pyOpenSSL==16.2.0',         # src.http_ssl
        'termcolor==1.1.0',          # logging

    ],
    include_package_data=True,      # archivos a incluir en MANIFEST.in
)
