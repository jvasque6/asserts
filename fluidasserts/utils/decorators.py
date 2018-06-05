# -*- coding: utf-8 -*-

"""This module enables decorators for registry and usage tracking purposes."""

import atexit
import functools
import sys
from typing import Callable, Any

import mixpanel
from fluidasserts import MP, CLIENT_ID

UNITTEST = False

if bool(getattr(sys, 'ps1', sys.flags.interactive)):
    UNITTEST = True


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
        try:
            MP.track(CLIENT_ID, func.__module__ + ' -> ' + func.__name__)
        except mixpanel.MixpanelException:
            pass
        if UNITTEST:
            return func(*args, **kwargs)
        else:
            atexit.register(func, *args, **kwargs)
    return decorated
