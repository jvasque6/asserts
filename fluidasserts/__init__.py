# -*- coding: utf-8 -*-

"""Fluid Asserts main package."""

# pylint: disable=no-name-in-module
# standard imports
from __future__ import absolute_import

import datetime
import inspect
import os
import sys
from collections import OrderedDict

# 3rd party imports
import oyaml as yaml

from pkg_resources import get_distribution, DistributionNotFound
from pygments import highlight
from pygments.lexers import PropertiesLexer
from pygments.formatters import TerminalFormatter
from pygments.token import Keyword, Name, Comment, String, Error, \
    Number, Operator, Generic, Token, Whitespace
from pygments.util import UnclosingTextIOWrapper

# local imports
# none

# pylint: disable=too-many-instance-attributes
# pylint: disable=too-few-public-methods
# pylint: disable=no-member
# pylint: disable=global-statement
# Remove support for py2

if sys.version_info < (3,):
    print('Py2 is not longer supported. Please, use a Py3 interpreter to run \
Fluid Asserts')
    sys.exit(-1)

OUTFILE = sys.stdout

OPEN_COLORS = {
    Token: ('', ''),
    Whitespace: ('lightgray', 'darkgray'),
    Comment: ('darkred', 'red'),
    Comment.Preproc: ('darkred', 'red'),
    Keyword: ('darkblue', 'blue'),
    Keyword.Type: ('teal', 'turquoise'),
    Operator.Word: ('purple', 'fuchsia'),
    Name.Builtin: ('teal', 'turquoise'),
    Name.Function: ('darkgreen', 'green'),
    Name.Namespace: ('_teal_', '_turquoise_'),
    Name.Class: ('_darkgreen_', '_green_'),
    Name.Exception: ('teal', 'turquoise'),
    Name.Decorator: ('darkgray', 'lightgray'),
    Name.Variable: ('darkred', 'red'),
    Name.Constant: ('darkred', 'red'),
    Name.Attribute: ('lightgray', 'darkgray'),
    Name.Tag: ('blue', 'blue'),
    String: ('red', 'red'),
    Number: ('red', 'red'),
    Generic.Deleted: ('red', 'red'),
    Generic.Inserted: ('darkgreen', 'green'),
    Generic.Heading: ('**', '**'),
    Generic.Subheading: ('*purple*', '*fuchsia*'),
    Generic.Prompt: ('**', '**'),
    Generic.Error: ('red', 'red'),
    Error: ('red', 'red'),
}

CLOSE_COLORS = {
    Token: ('', ''),
    Whitespace: ('lightgray', 'darkgray'),
    Comment: ('lightgray', 'darkgray'),
    Comment.Preproc: ('teal', 'turquoise'),
    Keyword: ('darkblue', 'blue'),
    Keyword.Type: ('teal', 'turquoise'),
    Operator.Word: ('purple', 'fuchsia'),
    Name.Builtin: ('teal', 'turquoise'),
    Name.Function: ('darkgreen', 'green'),
    Name.Namespace: ('_teal_', '_turquoise_'),
    Name.Class: ('_darkgreen_', '_green_'),
    Name.Exception: ('teal', 'turquoise'),
    Name.Decorator: ('darkgray', 'lightgray'),
    Name.Variable: ('darkred', 'red'),
    Name.Constant: ('darkred', 'red'),
    Name.Attribute: ('lightgray', 'darkgray'),
    Name.Tag: ('blue', 'blue'),
    String: ('darkgreen', 'green'),
    Number: ('darkgreen', 'green'),
    Generic.Deleted: ('red', 'red'),
    Generic.Inserted: ('darkgreen', 'green'),
    Generic.Heading: ('**', '**'),
    Generic.Subheading: ('*purple*', '*fuchsia*'),
    Generic.Prompt: ('**', '**'),
    Generic.Error: ('red', 'red'),
    Error: ('darkgreen', 'green'),
}

UNKNOWN_COLORS = {
    Token: ('', ''),
    Whitespace: ('lightgray', 'darkgray'),
    Comment: ('lightgray', 'darkgray'),
    Comment.Preproc: ('teal', 'turquoise'),
    Keyword: ('darkblue', 'blue'),
    Keyword.Type: ('teal', 'turquoise'),
    Operator.Word: ('purple', 'fuchsia'),
    Name.Builtin: ('teal', 'turquoise'),
    Name.Function: ('darkgreen', 'green'),
    Name.Namespace: ('_teal_', '_turquoise_'),
    Name.Class: ('_darkgreen_', '_green_'),
    Name.Exception: ('teal', 'turquoise'),
    Name.Decorator: ('darkgray', 'lightgray'),
    Name.Variable: ('darkred', 'red'),
    Name.Constant: ('darkred', 'red'),
    Name.Attribute: ('lightgray', 'darkgray'),
    Name.Tag: ('blue', 'blue'),
    String: ('darkgray', 'darkgray'),
    Number: ('darkgray', 'darkgray'),
    Generic.Deleted: ('red', 'red'),
    Generic.Inserted: ('darkgreen', 'green'),
    Generic.Heading: ('**', '**'),
    Generic.Subheading: ('*purple*', '*fuchsia*'),
    Generic.Prompt: ('**', '**'),
    Generic.Error: ('red', 'red'),
    Error: ('darkgray', 'darkgray'),
}


def enable_win_colors():
    """Enable windows colors."""
    global OUTFILE
    if sys.platform in ('win32', 'cygwin'):  # pragma: no cover
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


def check_cli():
    """Check execution from CLI."""
    if 'FA_CLI' not in os.environ:
        enable_win_colors()
        cli_warn = """
########################################################
## INVALID OUTPUT. PLEASE, RUN ASSERTS USING THE CLI. ##
########################################################
"""
        highlight(cli_warn, PropertiesLexer(),
                  TerminalFormatter(colorscheme=OPEN_COLORS), OUTFILE)


def get_caller_module(depth=3):
    """Get caller module."""
    frm = inspect.stack()[depth]
    mod = inspect.getmodule(frm[0])
    caller = mod.__name__
    return caller


def get_caller_function():
    """Get caller function."""
    deep = 3
    function = sys._getframe(deep).f_code.co_name  # noqa
    while function.startswith('_'):
        function = sys._getframe(deep).f_code.co_name  # noqa
        deep += 1
    return function


class Message(object):
    """Output message class."""

    def __init__(self, status, message, details, references):
        """Constructor method."""
        self.__ref_base = 'https://fluidattacks.com/web/es/defends/'
        self.__status_codes = ['OPEN', 'CLOSED', 'UNKNOWN', 'ERROR']
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
            style = OPEN_COLORS
        elif self.status == 'CLOSED':
            style = CLOSE_COLORS
        elif self.status == 'UNKNOWN':
            style = UNKNOWN_COLORS
        highlight(message, PropertiesLexer(),
                  TerminalFormatter(colorscheme=style), OUTFILE)


def show_close(message, details=None, refs=None):
    """Show close message."""
    check_cli()
    message = Message('CLOSED', message, details, refs)
    message.as_yaml()


def show_open(message, details=None, refs=None):
    """Show close message."""
    check_cli()
    message = Message('OPEN', message, details, refs)
    message.as_yaml()


def show_unknown(message, details=None, refs=None):
    """Show close message."""
    check_cli()
    message = Message('UNKNOWN', message, details, refs)
    message.as_yaml()


def check_boolean_env_var(var_name):
    """Check value of boolean environment variable."""
    if var_name in os.environ:
        accepted_values = ['true', 'false']
        if os.environ[var_name] not in accepted_values:
            print(var_name + ' env variable is \
    set but with an unknown value. It must be "true" or "false".')
            sys.exit(-1)


def show_banner():
    """Show Asserts banner."""
    enable_win_colors()
    header = """
---
# Fluid Asserts (v. {})
#  ___
# | >>|> fluid
# |___|  attacks, we hack your software
#
# Loading attack modules ...
""".format(__version__)

    highlight(header, PropertiesLexer(),
              TerminalFormatter(colorscheme=OPEN_COLORS), OUTFILE)


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
else:  # pragma: no cover
    __version__ = _DIST.version


check_boolean_env_var('FA_STRICT')
check_boolean_env_var('FA_NOTRACK')
