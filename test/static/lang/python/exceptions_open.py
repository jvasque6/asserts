"""
exceptions_open.py.

This is a test module to check exceptions.
"""
# pylint: disable=bare-except
try:
    print('Hello world')
except:
    print('a')
try:
    print('Hello world')
except:
    pass
try:
    print('Hello world')
except IndexError:
    pass
try:
    print('Hello world')
except (IndexError, AttributeError):
    pass
try:
    print('Hello world')
except IndexError:
    print('a')
