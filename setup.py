# -*- coding: utf-8 -*-

"""Archivo estandar para generación de instalador.

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
        'fluidasserts',
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
        'configobj==5.0.6',         # fluidasserts
        'PyPDF2==1.26.0',           # fluidasserts.pdf
        'Flask==0.11.1',            # fluidasserts.http
        'requests==2.10.0',         # fluidasserts.http
        'requests-oauthlib==0.6.2', # fluidasserts.http
        'cryptography==1.4',        # fluidasserts.http_ssl
        'paramiko==2.0.2',          # fluidasserts.ssh
    ],
    include_package_data=True,      # archivos a incluir en MANIFEST.in
)
