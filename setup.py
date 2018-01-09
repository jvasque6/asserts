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
        'fluidasserts.service',
        'fluidasserts.utils',
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
        'PyPDF2==1.26.0',            # src.format.pdf
        'requests==2.13.0',          # src.service.http
        'requests-oauthlib==0.8.0',  # src.service.http
        'cryptography==2.1.2',       # src.service.ssl
        'certifi==2017.7.27.1',      # src.service.ssl
        'ldap3==2.2.2',              # src.service.ldap
        'paramiko==2.1.2',           # src.helper.ssh_helper
        'pywinrm==0.2.2',            # src.helper.winrm_helper
        'beautifulsoup4==4.5.3',     # src.format.html
        'dnspython==1.15.0',         # src.service.dns
        'tlslite-ng==0.7.0-alpha3',  # src.service.ssl
        'pyOpenSSL==16.2.0',         # src.service.ssl
        'colorama==0.3.9',           # logging
        'pysmb==1.1.19',             # src.service.smb
        'mixpanel==4.3.2',           # src.utils.decorators
        'requests_ntlm==1.0.0',      # src.helper.http_helper
        'pytesseract==0.1.7',        # src.format.captcha
        'pillow==4.3.0',             # src.format.captcha
    ],
    include_package_data=True,      # archivos a incluir en MANIFEST.in
)
