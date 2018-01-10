# -*- coding: utf-8 -*-

"""Modulo para verificacion del webservices expuestos o vulnerables.

Este modulo permite verificar vulnerabilidades sobre webservices:

    * Uso de REST API sin credenciales o token
    * Uso de SOAP sin credenciales o token
"""
# standard imports
import logging

# third party imports
# None

# local imports
from fluidasserts.utils.decorators import track

LOGGER = logging.getLogger('FLUIDAsserts')


"""
Verifica si los métodos del container estan disponibles sin autenticación
En caso contrario retorna un error 404 si no se encuentra disponible o
403 en caso de que necesite autenticación

Version preeliminar
"""


@track
def soap_is_enable():
    """Verifica si el WS SOAP esta habilitado."""
    pass
