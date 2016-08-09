# -*- coding: utf-8 -*-

"""Modulo para pruebas de SMTP.

Este modulo contiene las funciones necesarias para probar si el modulo de
SMTP se encuentra adecuadamente implementado.
"""

# standard imports
# none

# 3rd party imports
# none

# local imports
from fluidasserts import smtp


smtp.has_vrfy('127.0.0.1', 10025)
