# -*- coding: utf-8 -*-

"""This module enables decorators for registry and usage tracking purposes."""

# standard imports
import sys
import functools
from typing import Callable, Any
from .tracking import mp_track

# 3rd party imports
import yaml

# local imports
from fluidasserts.utils.cli import colorize_text
from fluidasserts.utils.cli import enable_win_colors

OUTFILE = sys.stderr


def track(func: Callable) -> Callable:
    """Log and registers function usage."""
    @functools.wraps(func)
    def decorated(*args, **kwargs) -> Any:  # noqa
        """Log and registers function usage."""
        mp_track(func.__module__ + ' -> ' + func.__name__)
        return func(*args, **kwargs)
    return decorated


def level(risk_level: str) -> Callable:
    """Create decorator factory."""
    def wrapper(func: Callable) -> Callable:
        """Give a risk level to each check."""
        @functools.wraps(func)
        def decorated(*args, **kwargs) -> Any:  # noqa
            """Give a risk level to each check."""
            enable_win_colors()
            msg = '- Running: ' + func.__module__ + ' -> ' + func.__name__
            colorize_text(msg)
            ret_val = func(*args, **kwargs)
            risk = {'risk-level': risk_level}
            message = yaml.safe_dump(risk, default_flow_style=False,
                                     explicit_start=False)
            print(message, flush=True)
            return ret_val
        return decorated
    return wrapper
