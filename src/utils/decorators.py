import functools
from mixpanel import Mixpanel

High = 3
Medium = 2
Low = 1

LEVELS = (Low, Medium, High)
PROJECT_TOKEN = 'bf2c390e732c4aa0e9b89c8dec78360b'
CLIENT_ID = 'beta tester'


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
        return func(*args, **kwargs)
    mp = Mixpanel(PROJECT_TOKEN)
    mp.track(CLIENT_ID, func.__name__)
    return decorated
