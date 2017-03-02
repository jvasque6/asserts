# -*- coding: utf-8 -*-

"""Paquete format de FLUIDAsserts.

Config
"""

# standard imports
import logging.config
import os
import tempfile

# 3rd party imports
# none

# local imports
# none


# create logger
logger = logging.getLogger('FLUIDAsserts')
logger.setLevel(logging.DEBUG)

# create console handler and set level to debug
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
tmp_dir = tempfile.gettempdir()
file_handler = logging.FileHandler(
    os.path.join(tmp_dir, 'fluidasserts.log')
    )
file_handler.setLevel(logging.DEBUG)

# create formatter
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# add formatter to console_handler
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)

# add handlers to logger
logger.addHandler(console_handler)
logger.addHandler(file_handler)
