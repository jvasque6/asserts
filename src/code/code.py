# -*- coding: utf-8 -*-

"""Code module.

This module allows to check Code vulnerabilities
"""

# standard imports
import re

# 3rd party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track


def __generic_code_assert(code_file, expected_regex):
    """Check if a text is present in code."""
    with open(code_file) as code_fd:
        if re.search(str(expected_regex), code_fd.read(), re.IGNORECASE):
            return True
        return False


@track
def has_text(code_file, expected_text):
    """Check if a bad text is present."""
    ret = __generic_code_assert(code_file, expected_text)
    if ret:
        show_open('{} Bad text present in code, Details={}'.
                  format(code_file, expected_text))
        return True
    show_close('{} Bad text not present in code, Details={}'.
               format(code_file, expected_text))
    return False


@track
def has_not_text(code_file, expected_text):
    """Check if a required text is not present."""
    ret = __generic_code_assert(code_file, expected_text)
    if not ret:
        show_open('{} Expected text not present in code, Details={}'.
                  format(code_file, expected_text))
        return True
    show_close('{} Expected text present in code, Details={}'.
               format(code_file, expected_text))
    return False
