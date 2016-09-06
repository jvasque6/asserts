# -*- coding: utf-8 -*-

"""Paquete principal de FLUIDAsserts.

FLUIDAsserts verifica si una vulnerabilidad se encuentra abierta o cerrada.

Para ello en este paquete existe por cada protocolo o formato un módulo que
implementa las verificaciones necesarias propias de cada tecnologia.

Las verificaciones son predicados, es decir, funciones que retornan verdadero
cuando la vulnerabilidad se encuentra aun abierta y falso cuando ya esta se
encuentra cerrada.

Desde este paquete se carga el archivo de configuración que contiene todos
los detalles sobre formato y ubicación de los logs generados por la
herramienta.
"""

# standard imports
import logging.config

# 3rd party imports
from configobj import ConfigObj
from validate import Validator

# local imports
# none

# pylint: disable=C0103
cfg = ConfigObj('conf/conf.cfg', configspec='conf/conf.spec')
cfg.validate(Validator())  # exit si la validación falla

logging.config.dictConfig(cfg['logging'])
