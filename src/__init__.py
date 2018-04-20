# -*- coding: utf-8 -*-

"""FLUIDAsserts main package."""

# pylint: disable=no-name-in-module
# standard imports
import datetime
import inspect
import json
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
from pygments.lexers import YamlLexer, JsonLexer
from pygments.formatters import TerminalTrueColorFormatter

# local imports
# none

# pylint: disable=too-many-instance-attributes


def get_caller_module():
    """Get caller module."""
    frm = inspect.stack()[3]
    mod = inspect.getmodule(frm[0])
    caller = mod.__name__
    return caller


def get_caller_function():
    """Get caller function."""
    return sys._getframe(3).f_code.co_name  # noqa


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

    def __build_message(self):
        """Build message dict."""
        assert self.status in self.__status_codes
        assert self.message is not None
        if self.details is None:
            details = 'None'
        else:
            import operator
            details = sorted(self.details.items(), key=operator.itemgetter(0))

        data = [('when', self.date),
                ('status', self.status),
                ('message', self.message),
                ('details', OrderedDict(details)),
                ('caller_module', self.caller_module),
                ('caller_function', self.caller_function)]
        if self.references:
            data.append(('references', self.references))
        return OrderedDict(data)

    def as_json(self):
        """Get JSON representation of message."""
        message = json.dumps(self.__build_message())
        print(highlight(message, JsonLexer(), TerminalTrueColorFormatter()))

    def as_yaml(self):
        """Get YAML representation of message."""
        message = yaml.dump(self.__build_message(), default_flow_style=False)
        print(highlight(message, YamlLexer(), TerminalTrueColorFormatter()))

    def as_logger(self):
        """Get logger representation of message."""
        message = self.__build_message()
        if message['references']:
            template = """\033[1mStatus:\033[0m {}
                                                \033[1mResult:\033[0m {}
                                                \033[1mDetails:\033[0m {}
                                                \033[1mReferences:\033[0m {}
                                                \033[1mCaller Module:\033[0m {}
                                                \033[1mCaller Function:\033[0m {}
                                                """
            msg = template.format(message['status'], message['message'],
                                  message['details'], message['references'],
                                  message['caller_module'],
                                  message['caller_function'])
        else:
            template = """\033[1mStatus:\033[0m {}
                                                \033[1mResult:\033[0m {}
                                                \033[1mDetails:\033[0m {}
                                                \033[1mCaller Module:\033[0m {}
                                                \033[1mCaller Function:\033[0m {}
                                                """
            msg = template.format(message['status'], message['message'],
                                  message['details'],
                                  message['caller_module'],
                                  message['caller_function'])
        LOGGER.info(msg)

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
---
# FLUIDAsserts by FLUIDAttacks (https://fluidattacks.com)
# All rights reserved.
# Loading attack modules ...
    """
    print(highlight(HEADER, YamlLexer(), TerminalTrueColorFormatter()))

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
