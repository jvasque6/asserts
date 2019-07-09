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


def test_get_sha256():
    """Test add_info."""
    expected_sha256: str = \
        'e988f5d769a5fc3b32031fa46c75256f5c60647c0d958e1ca59816ba58643ecb'
    assert expected_sha256 == generic.get_sha256(
        'test/static/format/jks/open/1.jks')

#
# Closing tests
#


def test_check_function_close():
    """Test a function that will return closed."""
    assert not generic.check_function(is_greater, 1, 2)
    assert not generic.check_function(is_greater, 'a', 2)
    assert not generic.check_function(is_greater_async, 1, 2)
    assert not generic.check_function(is_greater_async, 'a', 2)
