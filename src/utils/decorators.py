# -*- coding: utf-8 -*-
"""FLUIDAsserts decorators."""

import functools
import mixpanel
from fluidasserts import MP, CLIENT_ID


def track(func):
    """Decorator."""
    @functools.wraps(func)
    def decorated(*args, **kwargs):
        """Decorate function."""
        try:
            MP.track(CLIENT_ID, func.__module__ + ' -> ' + func.__name__)
        except mixpanel.MixpanelException:
            pass
        return func(*args, **kwargs)
    return decorated
