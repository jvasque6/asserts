# -*- coding: utf-8 -*-

"""Paquete service de FLUIDAsserts.

Verificaciones de servicios específicos
"""

# standard imports
import logging.config
import os
from pkg_resources import resource_stream

# 3rd party imports
from configobj import ConfigObj
from validate import Validator

# local imports
# none


try:
    _LOG_CONFIG_FILE = 'conf.cfg'
    _LOG_CONFIG_LOCATION = resource_stream(__name__, _LOG_CONFIG_FILE)

    _LOG_SPEC_FILE = 'conf.spec'
    _LOG_SPEC_LOCATION = resource_stream(__name__, _LOG_SPEC_FILE)
except IOError:
    _LOG_CONFIG_LOCATION = os.path.join(os.path.curdir, 'conf',
                                        'conf.cfg')
    _LOG_SPEC_LOCATION = os.path.join(os.path.curdir, 'conf',
                                      'conf.spec')

# pylint: disable=C0103
cfg = ConfigObj(_LOG_CONFIG_LOCATION, configspec=_LOG_SPEC_LOCATION)
cfg.validate(Validator())  # exit si la validacion falla

logging.config.dictConfig(cfg['logging'])
