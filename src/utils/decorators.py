import functools

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
