# -*- coding: utf-8 -*-

"""Archivo estandar para generación de instalador.

Este modulo define los parametros minimos requeridos para generar
un instalador estandar de FLUIDAsserts.
"""

#
# TODO(ralvarez): Solo si incluye tasks.py y no *.py porque el linter
# falla en un ambiente virtual de python.  Ver referencia.
# https://github.com/PyCQA/pylint/issues/73
#
# pylint: disable=import-error,no-name-in-module

from distutils.core import setup

setup(name='FLUIDAsserts',
      description='Assertion Library for Security Assumptions',
      version='0.1',
      url='https://fluid.la/',
      author='FLUID Engineering Team',
      author_email='engineering@fluid.la',)
