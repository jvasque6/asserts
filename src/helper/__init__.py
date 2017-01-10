# -*- coding: utf-8 -*-

"""Paquete helper de FLUIDAsserts.

Módulos de ayuda
"""

# standard imports
import logging.config
from pkg_resources import resource_stream

# 3rd party imports
from configobj import ConfigObj
from validate import Validator

# local imports
# none


try:
    _log_config_file = 'conf.cfg'
    _log_config_location = resource_stream(__name__, _log_config_file)

    _log_spec_file = 'conf.spec'
    _log_spec_location = resource_stream(__name__, _log_spec_file)
except Exception:
    _log_config_location = 'conf/conf.cfg'
    _log_spec_location = 'conf/conf.spec'

# pylint: disable=C0103
cfg = ConfigObj(_log_config_location, configspec=_log_spec_location)
cfg.validate(Validator())  # exit si la validación falla

logging.config.dictConfig(cfg['logging'])
