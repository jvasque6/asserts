# -*- coding: utf-8 -*-

"""Archivo estandar para generacion de instalador.

Este modulo define los parametros minimos requeridos para generar
un instalador estandar de FLUIDAsserts.
"""
import time
from setuptools import setup

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
        'fluidasserts.proto',
        'fluidasserts.code',
        'fluidasserts.utils',
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
        'Development Status :: 2 - Pre-Alpha',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
    ],
    install_requires=[
        'configobj==5.0.6',          # fluidasserts
        'PyPDF2==1.26.0',            # fluidasserts.format.pdf
        'requests==2.18.4',          # fluidasserts.proto.http
        'requests-oauthlib==0.8.0',  # fluidasserts.proto.http
        'cryptography==2.2.2',       # fluidasserts.proto.ssl
        'certifi==2018.4.16',        # fluidasserts.proto.ssl
        'ldap3==2.5',                # fluidasserts.proto.ldap
        'paramiko==2.4.1',           # fluidasserts.helper.ssh_helper
        'pywinrm==0.3.0',            # fluidasserts.helper.winrm_helper
        'beautifulsoup4==4.6.0',     # fluidasserts.helper.http_helper
        'dnspython==1.15.0',         # fluidasserts.proto.dns
        'tlslite-ng==0.7.4',         # fluidasserts.proto.ssl
        'pyOpenSSL==17.5.0',         # fluidasserts.proto.ssl
        'colorama==0.3.9',           # logging
        'pysmb==1.1.22',             # fluidasserts.proto.smb
        'mixpanel==4.3.2',           # fluidasserts.utils.decorators
        'requests_ntlm==1.1.0',      # fluidasserts.helper.http_helper
        'pytesseract==0.2.0',        # fluidasserts.format.captcha
        'pillow==5.1.0',             # fluidasserts.format.captcha
        'pyparsing==2.2.0',          # fluidasserts.code
        'oyaml==0.4',                # fluidasserts
        'pygments==2.2.0',           # fluidasserts
    ],
    include_package_data=True,      # archivos a incluir en MANIFEST.in
)
