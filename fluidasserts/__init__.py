# -*- coding: utf-8 -*-

"""Fluid Asserts main package."""

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

# local imports
# none

# pylint: disable=too-many-instance-attributes
# pylint: disable=too-few-public-methods

# Remove support for py2

if sys.version_info < (3,):
    print('Py2 is not longer supported. Please, use a Py3 interpreter to run \
Fluid Asserts')
    sys.exit(-1)


def check_cli():
    """Check execution from CLI."""
    if 'FA_CLI' not in os.environ:
        cli_warn = """
########################################################
## INVALID OUTPUT. PLEASE, RUN ASSERTS USING THE CLI. ##
########################################################
"""
        print(cli_warn)


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


class Message():
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
        return yaml.dump(self.__build_message(), default_flow_style=False,
                         explicit_start=True)


def show_close(message, details=None, refs=None):
    """Show close message."""
    check_cli()
    message = Message('CLOSED', message, details, refs)
    print(message.as_yaml(), end='', flush=True)


def show_open(message, details=None, refs=None):
    """Show open message."""
    check_cli()
    message = Message('OPEN', message, details, refs)
    print(message.as_yaml(), end='', flush=True)


def show_unknown(message, details=None, refs=None):
    """Show unknown message."""
    check_cli()
    message = Message('UNKNOWN', message, details, refs)
    print(message.as_yaml(), end='', flush=True)


def check_boolean_env_var(var_name):
    """Check value of boolean environment variable."""
    if var_name in os.environ:
        accepted_values = ['true', 'false']
        if os.environ[var_name] not in accepted_values:
            print(var_name + ' env variable is \
    set but with an unknown value. It must be "true" or "false".')
            sys.exit(-1)


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
