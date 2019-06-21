#!/usr/bin/python3

# -*- coding: utf-8 -*-

"""Asserts generic meta-method."""

# standard imports
import sys
import asyncio

# 3rd party imports
import yaml
from typing import Callable

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts import show_metadata
from fluidasserts import method_stats_set_owner
from fluidasserts.utils.decorators import track, level, notify

# pylint: disable=broad-except


@notify
@level('low')
@track
def check_function(func: Callable, *args, **kwargs) -> bool:
    """Run arbitrary code and return results in Asserts format.

    This is useful for verifying very specific scenarios.

    :param func: Callable function that will return True if the
    vulnerability is found open or False (or any Python null value) if found
    closed.
    :param *args: Positional parameters that will be passed to func.
    :param *kwargs: Keyword parameters that will be passed to func.
    """
    metadata = kwargs.pop('metadata', None)
    try:
        if asyncio.iscoroutinefunction(func):
            loop = asyncio.new_event_loop()
            futr = asyncio.gather(func(*args, **kwargs), loop=loop)
            ret, = loop.run_until_complete(futr)
            loop.close()
        else:
            ret = func(*args, **kwargs)
    except Exception as exc:
        show_unknown('Function returned an error',
                     details=dict(metadata=metadata,
                                  function_call=dict(args=args,
                                                     kwargs=kwargs),
                                  error=repr(exc).replace(':', ',')))
    else:
        if ret:
            show_open('Function check was found open',
                      details=dict(metadata=metadata,
                                   function_call=dict(args=args,
                                                      kwargs=kwargs,
                                                      return_value=ret)))
            return True
        else:
            show_close('Function check was found closed',
                       details=dict(metadata=metadata,
                                    function_call=dict(args=args,
                                                       kwargs=kwargs,
                                                       return_value=ret)))
    return False


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
    method_stats_set_owner(finding)
    message = yaml.safe_dump({'finding': finding},
                             default_flow_style=False,
                             explicit_start=True,
                             allow_unicode=True)
    print(message, end='', flush=True)
    print(message, end='', flush=True, file=sys.stderr)
    return True
