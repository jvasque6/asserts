# -*- coding: utf-8 -*-

"""Modulo para verificacion del webservices expuestos o vulnerables.

Este modulo permite verificar vulnerabilidades sobre webservices:

	* Uso de REST API sin credenciales o token
	* Uso de SOAP sin credenciales o token
"""
# standard imports
import logging
import socket

# third party imports
# none

# local imports
# none
from suds.client import Client

logger = logging.getLogger('FLUIDAsserts')


"""
Verifica si los métodos del container estan disponibles sin autenticación
En caso contrario retorna un error 404 si no se encuentra disponible o
403 en caso de que necesite autenticación

Version preeliminar
"""


def soap_is_enable(wsdl):
	"""
	wsdl: Ruta al contenedor htttp:....?wsdl
	"""
    try:
        client = Client(wsdl)
        temp = str(client)
        logger.info('Checking Webservices, Details=%s, %s',
                    wsdl, temp)
    except Exception as e:
        print(e)

 def rest_is_enable(rest):
 	pass
