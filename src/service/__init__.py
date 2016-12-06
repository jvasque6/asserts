# -*- coding: utf-8 -*-

"""Paquete service de FLUIDAsserts.

Verificaciones de servicios específicos
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
