# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.generic."""

# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts.utils import generic


# Test function
def is_greater(x, y):
    """Test function."""
    return x > y

#
# Open tests
#


def test_check_function_open():
    """Test a function that will return open."""
    assert generic.check_function(is_greater, 3, 2)


def test_add_info():
    """Test add_info."""
    assert generic.add_finding('FIN.0001: test finding')


#
# Closing tests
#


def test_check_function_close():
    """Test a function that will return closed."""
    assert not generic.check_function(is_greater, 1, 2)
    assert not generic.check_function(is_greater, 'a', 2)
