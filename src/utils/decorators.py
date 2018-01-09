# -*- coding: utf-8 -*-
"""Decoradores de FLUIDAsserts."""

import functools
import mixpanel
from fluidasserts import mp, CLIENT_ID


def track(func):
    """Decorator."""
    @functools.wraps(func)
    def decorated(*args, **kwargs):
        """Decorated function."""
        try:
            mp.track(CLIENT_ID, func.__module__ + ' -> ' + func.__name__)
        except mixpanel.MixpanelException:
            pass
        return func(*args, **kwargs)
    return decorated
