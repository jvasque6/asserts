# -*- coding: utf-8 -*-

"""This module enables decorators for registry and usage tracking purposes."""

import functools
from typing import Callable, Any

from .tracking import mp_track


def track(func: Callable) -> Callable:
    """
    Decorator.

    Logs and registers function usage.
    """
    @functools.wraps(func)
    def decorated(*args, **kwargs) -> Any:  # noqa
        """
        Decorate function.

        Logs and registers function usage.
        """
        mp_track(func.__module__ + ' -> ' + func.__name__)
        return func(*args, **kwargs)
    return decorated
