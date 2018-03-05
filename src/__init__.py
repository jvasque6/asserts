# -*- coding: utf-8 -*-

"""FLUIDAsserts main package."""

# standard imports
import json
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

# pylint: disable=too-many-instance-attributes


class Message(object):
    """Output message class."""

    def __init__(self, status, message, details, references):
        """Constructor method."""
        self.__ref_base = 'https://fluidattacks.com/web/es/defends/'
        self.__status_codes = ['OPEN', 'CLOSE', 'UNKNOWN', 'ERROR']
        self.status = status
        self.message = message
        self.details = details
        if references:
            self.references = self.__ref_base + references
        else:
            self.references = None
        self.caller = sys._getframe(2).f_code.co_name  # noqa
        self.__open = Fore.WHITE + Back.RED + 'OPEN' + Style.RESET_ALL
        self.__close = Fore.WHITE + Back.GREEN + 'CLOSE' + \
            Style.RESET_ALL
        self.__unknown = Fore.BLACK + Back.WHITE + 'UNKNOWN' + \
            Style.RESET_ALL

    def __build_message(self):
        """Build message dict."""
        assert self.status in self.__status_codes
        assert self.message is not None
        if self.details is None:
            self.details = 'None'
        if self.references is None:
            self.references = 'None'

        if self.status == 'OPEN':
            status = self.__open
        elif self.status == 'CLOSE':
            status = self.__close
        elif self.status == 'UNKNOWN':
            status = self.__unknown

        ret = {'Status': status,
               'Message': self.message,
               'Details': self.details,
               'Caller': self.caller,
               'References': self.references}

        return ret

    def as_json(self):
        """Get JSON representation of message."""
        return json.dumps(self.__build_message())

    def as_logger(self):
        """Get logger representation of message."""
        message = self.__build_message()
        template = """\033[1mStatus:\033[0m {}
                                                \033[1mResult:\033[0m {}
                                                \033[1mDetails:\033[0m {}
                                                \033[1mReferences:\033[0m {}
                                                \033[1mCaller:\033[0m {}
                                                """
        msg = template.format(message['Status'], message['Message'],
                              message['Details'], message['References'],
                              message['Caller'])
        return msg


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

KEYS = ['FA_LICENSE_KEY', 'FA_USER_EMAIL']

for key in KEYS:
    try:
        os.environ[key]
    except KeyError:
        print(key + ' env variable must be set')
        sys.exit(-1)

if 'FA_STRICT' in os.environ:
    if os.environ['FA_STRICT'] != 'true' and \
       os.environ['FA_STRICT'] != 'false':
        print('FA_STRICT env variable is \
set but with an unknown value. It must be "true" or "false".')
        sys.exit(-1)

CLIENT_ID = os.environ['FA_LICENSE_KEY']
USER_EMAIL = os.environ['FA_USER_EMAIL']

try:
    HEADER = """
FLUIDAsserts by FLUIDAttacks (https://fluidattacks.com)
All rights reserved.
Loading modules...
    """
    HEADER_COL = Style.BRIGHT + Fore.WHITE + HEADER + Style.RESET_ALL
    print(HEADER_COL)

    MP = mixpanel.Mixpanel(PROJECT_TOKEN)
    MP.people_set(CLIENT_ID, {'$email': USER_EMAIL})
except mixpanel.MixpanelException:
    pass


def show_close(message, details=None, refs=None):
    """Show close message."""
    message = Message('CLOSE', message, details, refs)
    LOGGER.info(message.as_logger())


def show_open(message, details=None, refs=None):
    """Show close message."""
    message = Message('OPEN', message, details, refs)
    LOGGER.info(message.as_logger())
    if 'FA_STRICT' in os.environ:
        if os.environ['FA_STRICT'] == 'true':
            sys.exit(1)


def show_unknown(message, details=None, refs=None):
    """Show close message."""
    message = Message('UNKNOWN', message, details, refs)
    LOGGER.info(message.as_logger())
