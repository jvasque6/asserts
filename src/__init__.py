# -*- coding: utf-8 -*-

"""Paquete format de FLUIDAsserts.

Config
"""

# standard imports
import logging.config
import mixpanel
import os
from pkg_resources import get_distribution, DistributionNotFound
import tempfile
import sys

# 3rd party imports
from colorama import Fore, Back, Style, init

# local imports
# none

init(autoreset=True)

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


PROJECT_TOKEN = 'd6992587dea9caad619299d54a0f00f0'

KEYS = ['FLUIDASSERTS_LICENSE_KEY','FLUIDASSERTS_USER_EMAIL']

for key in KEYS:
    try:
        os.environ[key]
    except KeyError:
        print(key +' env variable must be set')
        sys.exit(-1)

CLIENT_ID = os.environ['FLUIDASSERTS_LICENSE_KEY']
USER_EMAIL = os.environ['FLUIDASSERTS_USER_EMAIL']

try:
    print('Loading modules...')
    mp = mixpanel.Mixpanel(PROJECT_TOKEN)
    mp.people_set(CLIENT_ID, {'$email': USER_EMAIL})
except mixpanel.MixpanelException:
    pass

def show_close(message=None):
    if message is None:
        text_to_show = 'CLOSE'
    else:
        text_to_show = message
    return Fore.WHITE + Back.GREEN + text_to_show + Style.RESET_ALL


def show_open(message=None):
    if message is None:
        text_to_show = 'OPEN'
    else:
        text_to_show = message
    return Fore.WHITE + Back.RED + text_to_show + Style.RESET_ALL


def show_unknown(message=None):
    if message is None:
        text_to_show = 'UNKNOWN'
    else:
        text_to_show = message
    return Fore.BLACK + Back.WHITE + text_to_show + Style.RESET_ALL
