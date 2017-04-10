# -*- coding: utf-8 -*-

"""Paquete format de FLUIDAsserts.

Config
"""

# standard imports
import logging.config
import os
from pkg_resources import get_distribution, DistributionNotFound
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


# Set __version__
try:
    _dist = get_distribution('fluidasserts')
    # Normalize case for Windows systems
    dist_loc = os.path.normcase(_dist.location)
    here = os.path.normcase(__file__)
    if not here.startswith(os.path.join(dist_loc, 'fluidasserts')):
        # not installed, but there is another version that *is*
        raise DistributionNotFound
except DistributionNotFound:
    __version__ = 'Please install this project with setup.py'
else:
    __version__ = _dist.version
