# -*- coding: utf-8 -*-

"""This module enables decorators for registry and usage tracking purposes."""

import functools
from typing import Callable, Any

import mixpanel
from fluidasserts import MP, CLIENT_ID


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
        except mixpanel.MixpanelException:  # pragma: no cover
            pass
        return func(*args, **kwargs)
    return decorated
