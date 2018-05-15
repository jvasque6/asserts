# -*- coding: utf-8 -*-
"""FLUIDAsserts decorators."""

import atexit
import functools
from typing import Callable
import mixpanel
from fluidasserts import MP, CLIENT_ID

UNITTEST = False


def track(func: Callable) -> Callable:
    """
    Decorator.

    Logs and registers function usage.
    """
    @functools.wraps(func)
    def decorated(*args, **kwargs) -> Callable:  # noqa
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
