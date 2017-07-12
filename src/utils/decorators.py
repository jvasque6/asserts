import functools
import mixpanel
import os
import sys
from fluidasserts import mp, CLIENT_ID

High = 3
Medium = 2
Low = 1

LEVELS = (Low, Medium, High)


def test_level(level):
    def wrapper(func):
        @functools.wraps(func)
        def decorated(*args, **kwargs):
            return func(*args, **kwargs)
        decorated.level = High
        if level in LEVELS:
            decorated.level = level
        return decorated
    return wrapper


def track(func):
    @functools.wraps(func)
    def decorated(*args, **kwargs):
        try:
            mp.track(CLIENT_ID, func.__module__ + ' -> ' + func.__name__)
        except mixpanel.MixpanelException:
            pass
        return func(*args, **kwargs)
    return decorated
