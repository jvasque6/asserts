# -*- coding: utf-8 -*-

"""Archivo estandar para generacion de instalador.

Este modulo define los parametros minimos requeridos para generar
un instalador estandar de FLUIDAsserts.
"""

from setuptools import setup

setup(
    name='FLUIDAsserts',
    description='Assertion Library for Security Assumptions',
    version='0.0.20170227.1',
    url='https://fluid.la/',
    author='FLUID Engineering Team',
    author_email='engineering@fluid.la',
    packages=[
        'fluidasserts',
        'fluidasserts.format',
        'fluidasserts.helper',
        'fluidasserts.os',
        'fluidasserts.service',
    ],
    data_files=[
        ('fluidasserts', ['conf/conf.cfg', 'conf/conf.spec']),
        ('fluidasserts/format', ['conf/conf.cfg', 'conf/conf.spec']),
        ('fluidasserts/helper', ['conf/conf.cfg', 'conf/conf.spec']),
        ('fluidasserts/os', ['conf/conf.cfg', 'conf/conf.spec']),
        ('fluidasserts/service', ['conf/conf.cfg', 'conf/conf.spec']),
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
        'requests==2.12.4',          # src.http
        'requests-oauthlib==0.7.0',  # src.http
        'cryptography==1.7.1',       # src.http_ssl
        'ldap3==2.1.1',              # src.ldap
        'paramiko==2.1.1',           # src.ssh_helper
        'pywinrm==0.2.2',            # src.winrm_helper
        'beautifulsoup4==4.5.1',     # src.html
        'lxml==3.7.1',     	     # src.http_helper
        'dnspython==1.15.0',         # src.dns
        'tlslite-ng==0.6.0',         # src.http_ssl

    ],
    include_package_data=True,      # archivos a incluir en MANIFEST.in
)
