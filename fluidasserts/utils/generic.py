#!/usr/bin/python3

# -*- coding: utf-8 -*-

"""Asserts generic meta-method."""

# standard imports
import sys

# 3rd party imports
from typing import Callable

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts import show_metadata
from fluidasserts import method_stats_set_owner
from fluidasserts.utils.cli import colorize_text
from fluidasserts.utils.cli import enable_win_colors
from fluidasserts.utils.decorators import track, level, notify

OUTFILE = sys.stderr

# pylint: disable=broad-except


@notify
@level('low')
@track
def check_function(func: Callable, *args, **kwargs):
    """Run arbitrary code and return results in Asserts format.

    This is useful for verifying very specific scenarios.

    :param func: Callable function that will return True if the
    vulnerability is found open or False (or any Python null value) if found
    closed.
    :param *args: Positional parameters that will be passed to func.
    :param *kwargs: Keyword parameters that will be passed to func.
    """
    try:
        ret = func(*args, **kwargs)
    except Exception as exc:
        show_unknown('Function returned an error',
                     details=dict(function=func.__name__,
                                  args=args, kwargs=kwargs,
                                  error=str(exc).replace(':', ',')))
        return False
    else:
        if ret:
            show_open('Function check was found open',
                      details=dict(function=func.__name__,
                                   args=args, kwargs=kwargs,
                                   ret=ret))
        else:
            show_close('Function check was found closed',
                       details=dict(function=func.__name__,
                                    args=args, kwargs=kwargs,
                                    ret=ret))
        return bool(ret)


def add_info(metadata: dict) -> bool:
    """Print arbitrary info in the Asserts output.

    :param metadata: Dict with data to be printed.
    """
    show_metadata(metadata)
    return True


def add_finding(finding: str) -> bool:
    """Print finding as part of the Asserts output.

    :param finding: Current project context.
    """
    enable_win_colors()
    method_stats_set_owner(finding)
    colorize_text('---')
    colorize_text('finding: ' + finding)
    return True
