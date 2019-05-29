# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.generic."""

# standard imports
import asyncio

# 3rd party imports
# None

# local imports
from fluidasserts.utils import generic


#
# Test functions
#


def is_greater(x, y):
    """Test function."""
    return x > y


async def is_greater_async(x, y):
    """Async test function."""
    await asyncio.sleep(1.0)
    return x > y


#
# Open tests
#


def test_check_function_open():
    """Test a function that will return open."""
    assert generic.check_function(is_greater, 3, 2)
    assert generic.check_function(is_greater_async, 3, 2)


def test_add_info():
    """Test add_info."""
    assert generic.add_finding('FIN.S.0001: test finding')


#
# Closing tests
#


def test_check_function_close():
    """Test a function that will return closed."""
    assert not generic.check_function(is_greater, 1, 2)
    assert not generic.check_function(is_greater, 'a', 2)
    assert not generic.check_function(is_greater_async, 1, 2)
    assert not generic.check_function(is_greater_async, 'a', 2)

test_check_function_open()
test_check_function_close()
