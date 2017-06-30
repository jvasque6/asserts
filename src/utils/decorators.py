import functools
import mixpanel
import os
import sys

High = 3
Medium = 2
Low = 1

LEVELS = (Low, Medium, High)
PROJECT_TOKEN = 'bf2c390e732c4aa0e9b89c8dec78360b'

KEYS = ['FLUIDASSERTS_LICENSE_KEY','FLUIDASSERTS_USER_EMAIL']

for key in KEYS:
    try:
        os.environ[key]
    except KeyError:
        print(key +' env variable must be set')
        sys.exit(-1)

CLIENT_ID = os.environ['FLUIDASSERTS_LICENSE_KEY']
USER_EMAIL = os.environ['FLUIDASSERTS_USER_EMAIL']


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
    try:
        mp = mixpanel.Mixpanel(PROJECT_TOKEN)
        mp.people_set(CLIENT_ID, {'$email': USER_EMAIL})
        mp.track(CLIENT_ID, func.__name__)
    except mixpanel.MixpanelException:
        pass
    return decorated
