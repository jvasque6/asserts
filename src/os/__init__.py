# -*- coding: utf-8 -*-

"""Paquete os de FLUIDAsserts.

Verificaciones a nivel de sistema operativo.
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
