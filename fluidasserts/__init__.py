# -*- coding: utf-8 -*-

"""FLUIDAsserts main package."""

# pylint: disable=no-name-in-module
# standard imports
import datetime
import inspect
import logging.config
import os
import tempfile
import sys
from collections import OrderedDict

# 3rd party imports
import mixpanel
import oyaml as yaml

from pkg_resources import get_distribution, DistributionNotFound
from pygments import highlight
from pygments.lexers import PropertiesLexer
from pygments.formatters import Terminal256Formatter
from pygments.style import Style
from pygments.styles import get_style_by_name
from pygments.token import Token

# local imports
# none

# pylint: disable=too-many-instance-attributes
# pylint: disable=too-few-public-methods
# pylint: disable=no-member

OUTFILE = sys.stdout

if sys.platform in ('win32', 'cygwin'):
    if sys.version_info > (3,):
        from pygments.util import UnclosingTextIOWrapper
        OUTFILE = UnclosingTextIOWrapper(sys.stdout.buffer)
    try:
        import colorama.initialise
    except ImportError:
        pass
    else:
        OUTFILE = colorama.initialise.wrap_stream(OUTFILE, convert=None,
                                                  strip=None,
                                                  autoreset=False,
                                                  wrap=True)


def get_caller_module():
    """Get caller module."""
    frm = inspect.stack()[3]
    mod = inspect.getmodule(frm[0])
    caller = mod.__name__
    return caller


def get_caller_function():
    """Get caller function."""
    return sys._getframe(3).f_code.co_name  # noqa


class MyStyleRed(Style):
    """Output red-colored message."""
    styles = {
        Token.Name.Attribute: '#ansiwhite',
        Token.Error: '#F74E4E',
        Token.String: '#F74E4E',
    }


class MyStyleGreen(Style):
    """Output green-colored message."""
    styles = {
        Token.Name.Attribute: '#ansiwhite',
        Token.Error: '#5FF74E',
        Token.String: '#5FF74E',
    }


class MyStyleGray(Style):
    """Output white-colored message."""
    styles = {
        Token.Name.Attribute: '#ansiwhite',
        Token.Error: '#929292',
        Token.String: '#929292',
    }


class Message(object):
    """Output message class."""

    def __init__(self, status, message, details, references):
        """Constructor method."""
        self.__ref_base = 'https://fluidattacks.com/web/es/defends/'
        self.__status_codes = ['OPEN', 'CLOSE', 'UNKNOWN', 'ERROR']
        self.date = datetime.datetime.now()
        self.status = status
        self.message = message
        self.details = details
        if references:
            self.references = self.__ref_base + references
        else:
            self.references = None
        self.caller_module = get_caller_module()
        self.caller_function = get_caller_function()
        self.check = '{}.{}'.format(self.caller_module, self.caller_function)

    def __build_message(self):
        """Build message dict."""
        assert self.status in self.__status_codes
        assert self.message is not None
        if self.details is None:
            details = 'None'
        else:
            import operator
            details = OrderedDict(sorted(self.details.items(),
                                         key=operator.itemgetter(0)))

        data = [('check', self.check),
                ('status', self.status),
                ('message', self.message),
                ('details', details),
                ('when', self.date)]
        if self.references:
            data.append(('references', self.references))
        return OrderedDict(data)

    def as_yaml(self):
        """Get YAML representation of message."""
        message = yaml.dump(self.__build_message(), default_flow_style=False,
                            explicit_start=True)
        if self.status == 'OPEN':
            style = MyStyleRed
        elif self.status == 'CLOSE':
            style = MyStyleGreen
        elif self.status == 'UNKNOWN':
            style = MyStyleGray
        highlight(message, PropertiesLexer(),
                  Terminal256Formatter(style=style), OUTFILE)


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


HEADER = """
---
# FLUIDAsserts by FLUIDAttacks (https://fluidattacks.com)
# All rights reserved.
# Loading attack modules ...
"""

HEADER_STYLE = get_style_by_name('igor')
highlight(HEADER, PropertiesLexer(), Terminal256Formatter(style=HEADER_STYLE),
          OUTFILE)
try:
    MP = mixpanel.Mixpanel(PROJECT_TOKEN)
    MP.people_set(CLIENT_ID, {'$email': USER_EMAIL})
except mixpanel.MixpanelException:
    pass


def show_close(message, details=None, refs=None):
    """Show close message."""
    message = Message('CLOSE', message, details, refs)
    message.as_yaml()


def show_open(message, details=None, refs=None):
    """Show close message."""
    message = Message('OPEN', message, details, refs)
    message.as_yaml()
    if 'FA_STRICT' in os.environ:
        if os.environ['FA_STRICT'] == 'true':
            sys.exit(1)


def show_unknown(message, details=None, refs=None):
    """Show close message."""
    message = Message('UNKNOWN', message, details, refs)
    message.as_yaml()
