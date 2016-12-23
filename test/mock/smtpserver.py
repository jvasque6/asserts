# -*- coding: utf-8 -*-

"""Servidor SMTP para hacer el mock correspondiente.

<abotero@fluid.la>
"""

# standard imports
import asyncore
import smtpd

# 3rd party imports
# none

# local imports
# none


SERVER = smtpd.SMTPServer(('127.0.0.1', 10025), None)
asyncore.loop()
