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


def _get_func_id(func: Callable) -> str:
    """Return a function identifier."""
    return f"{func.__module__} -> {func.__name__}"


def track(func: Callable) -> Callable:
    """Log and register function usage."""
    @functools.wraps(func)
    def decorated(*args, **kwargs) -> Any:  # noqa
        """Log and registers function usage."""
        mp_track(_get_func_id(func))
        return func(*args, **kwargs)
    return decorated


def level(risk_level: str) -> Callable:
    """Create decorator factory."""
    def wrapper(func: Callable) -> Callable:
        """Give a risk level to each check."""
        @functools.wraps(func)
        def decorated(*args, **kwargs) -> Any:  # noqa
            """Give a risk level to each check."""
            ret_val = func(*args, **kwargs)
            risk = {'risk-level': risk_level}
            message = yaml.safe_dump(risk,
                                     default_flow_style=False,
                                     explicit_start=False,
                                     allow_unicode=True)
            print(message, flush=True)
            return ret_val
        return decorated
    return wrapper


def notify(func: Callable) -> Callable:
    """Notify the user that the function is running."""
    @functools.wraps(func)
    def decorated(*args, **kwargs) -> Any:  # noqa
        """Notify the user that the function is running."""
        enable_win_colors()
        msg = f'- Running: {_get_func_id(func)}'
        colorize_text(msg)
        ret_val = func(*args, **kwargs)
        return ret_val
    return decorated
