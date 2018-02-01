# -*- coding: utf-8 -*-

"""FLUIDAsserts main package."""

# standard imports
import logging.config
import os
import tempfile
import sys
from pkg_resources import get_distribution, DistributionNotFound

# 3rd party imports
from colorama import Fore, Back, Style, init
import mixpanel

# local imports
# none

init(autoreset=True)

# create LOGGER
LOGGER = logging.getLogger('FLUIDAsserts')
LOGGER.setLevel(logging.DEBUG)

# create console handler and set level to debug
CONSOLE_HANDLER = logging.StreamHandler(sys.stdout)
CONSOLE_HANDLER.setLevel(logging.INFO)
TMP_DIR = tempfile.gettempdir()
FILE_HANDLER = logging.FileHandler(
    os.path.join(TMP_DIR, 'fluidasserts.log')
    )
FILE_HANDLER.setLevel(logging.DEBUG)

# create FORMATTER
FORMATTER = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# add FORMATTER to CONSOLE_HANDLER
CONSOLE_HANDLER.setFormatter(FORMATTER)
FILE_HANDLER.setFormatter(FORMATTER)

# add handlers to LOGGER
LOGGER.addHandler(CONSOLE_HANDLER)
LOGGER.addHandler(FILE_HANDLER)


# Set __version__
try:
    _DIST = get_distribution('fluidasserts')
    # Normalize case for Windows systems
    DIST_LOC = os.path.normcase(_DIST.location)
    HERE = os.path.normcase(__file__)
    if not HERE.startswith(os.path.join(DIST_LOC, 'fluidasserts')):
        # not installed, but there is another version that *is*
        raise DistributionNotFound
except DistributionNotFound:
    __version__ = 'Please install this project with setup.py'
else:
    __version__ = _DIST.version


PROJECT_TOKEN = '4ddf91a8a2c9f309f6a967d3462a496c'

KEYS = ['FLUIDASSERTS_LICENSE_KEY', 'FLUIDASSERTS_USER_EMAIL']

for key in KEYS:
    try:
        os.environ[key]
    except KeyError:
        print(key + ' env variable must be set')
        sys.exit(-1)

if 'FLUIDASSERTS_STRICT' in os.environ:
    if os.environ['FLUIDASSERTS_STRICT'] != 'true':
        print('FLUIDASSERTS_STRICT env variable is \
set but with an unknown value. It must be "true".')
        sys.exit(-1)

CLIENT_ID = os.environ['FLUIDASSERTS_LICENSE_KEY']
USER_EMAIL = os.environ['FLUIDASSERTS_USER_EMAIL']

try:
    print('Loading modules...')
    MP = mixpanel.Mixpanel(PROJECT_TOKEN)
    MP.people_set(CLIENT_ID, {'$email': USER_EMAIL})
except mixpanel.MixpanelException:
    pass


def show_close(message):
    """Show close message."""
    state = 'CLOSE'
    state_col = Fore.WHITE + Back.GREEN + state + Style.RESET_ALL
    text_to_show = '{state_col}: {message}'.format(state_col=state_col,
                                                   message=message)
    LOGGER.info(text_to_show)

def show_open(message):
    """Show close message."""
    state = 'OPEN'
    state_col = Fore.WHITE + Back.RED + state + Style.RESET_ALL
    text_to_show = '{state_col}: {message}'.format(state_col=state_col,
                                                   message=message)
    LOGGER.info(text_to_show)
    if 'FLUIDASSERTS_STRICT' in os.environ:
        if os.environ['FLUIDASSERTS_STRICT'] == 'true':
            sys.exit(1)


def show_unknown(message):
    """Show close message."""
    state = 'UNKNOWN'
    state_col = Fore.BLACK + Back.WHITE + state + Style.RESET_ALL
    text_to_show = '{state_col}: {message}'.format(state_col=state_col,
                                                   message=message)
    LOGGER.info(text_to_show)
