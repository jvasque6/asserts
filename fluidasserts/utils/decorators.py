# -*- coding: utf-8 -*-
"""FLUIDAsserts decorators."""

import atexit
import functools
import mixpanel
from fluidasserts import MP, CLIENT_ID

UNITTEST = False

def track(func):
    """Decorator."""
    @functools.wraps(func)
    def decorated(*args, **kwargs): # noqa
        """Decorate function."""
        try:
            MP.track(CLIENT_ID, func.__module__ + ' -> ' + func.__name__)
        except mixpanel.MixpanelException:
            pass
        if UNITTEST:
            return func(*args, **kwargs)
        else:
            atexit.register(func, *args, **kwargs)
    return decorated
