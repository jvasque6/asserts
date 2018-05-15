# -*- coding: utf-8 -*-

"""Ejemplo de script de explotación integrado que usa todas las funciones.

Este script posiblemente no sea ejecute satisfactoriamente pues depende
que todos los Mocks esten activos de forma simultanea, cuestion que solo
funciona desde los fixtures, pero busca servir como ejemplo acumulativo
aislado de los scripts de prueba, para visualizar como se invoca cada
función.
"""

# standar imports
# none

# 3rd party imports
# none

# local imports (solo fluidasserts)
from fluidasserts.service import ftp
from fluidasserts.format import pdf

# PDF
PDF_HARDENED = 'test/static/format/pdf/non-vulnerable.pdf'
PDF_VULNERABLE = 'test/static/format/pdf/vulnerable.pdf'
pdf.has_author(PDF_HARDENED)
pdf.has_author(PDF_VULNERABLE)
pdf.has_creator(PDF_HARDENED)
pdf.has_creator(PDF_VULNERABLE)
pdf.has_producer(PDF_HARDENED)
pdf.has_producer(PDF_VULNERABLE)

# FTP
FTP_HARDENED = '172.18.21.77'
FTP_VULNERABLE = '172.18.21.66'
ftp.is_admin_enabled(FTP_HARDENED, 'root1234')
ftp.is_admin_enabled(FTP_VULNERABLE, 'root123')
ftp.is_anonymous_enabled(FTP_HARDENED)
ftp.is_anonymous_enabled(FTP_VULNERABLE)
ftp.user_without_password(FTP_HARDENED, 'faustino')
ftp.user_without_password(FTP_VULNERABLE, 'dario')
ftp.is_a_valid_user(FTP_HARDENED, 'faustino', 'faustino1234')
ftp.is_a_valid_user(FTP_VULNERABLE, 'faustino', 'faustino123')
