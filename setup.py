# -*- coding: utf-8 -*-

"""Archivo estandar para generacion de instalador.

Este modulo define los parametros minimos requeridos para generar
un instalador estandar de FLUIDAsserts.
"""

from setuptools import setup

setup(
    name='FLUIDAsserts',
    description='Assertion Library for Security Assumptions',
    version='0.1',
    url='https://fluid.la/',
    author='FLUID Engineering Team',
    author_email='engineering@fluid.la',
    packages=[
        'fluidasserts.format',
        'fluidasserts.helper',
        'fluidasserts.os',
        'fluidasserts.service',
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
        'requests==2.10.0',          # src.http
        'requests-oauthlib==0.6.2',  # src.http
        'cryptography==1.4',         # src.http_ssl
        'ldap3==1.2.2',              # src.ldap
        'paramiko==2.0.2',           # src.ssh_helper
        'pywinrm==0.2.1',            # src.winrm_helper
        'beautifulsoup4==4.5.1',     # src.html
        'dnspython==1.15.0',         # src.dns

    ],
    include_package_data=True,      # archivos a incluir en MANIFEST.in
)
