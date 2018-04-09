# -*- coding: utf-8 -*-

"""Code helper.

This module has helper functions for code modules
"""

# standard imports
import inspect
import os

# 3rd party imports
# None

# local imports
from pyparsing import Or, ParseException

LANGUAGE_SPECS = {
    'java':{
        'extensions': ['java'],
        'block_comment_start': '/*',
        'block_comment_end': '*/',
        'line_comment': ['//'],
    },
    'rpgle':{
        'extensions': ['rpg', 'rpgle'],
        'block_comment_start': None,
        'block_comment_end': None,
        'line_comment': ['//', '*'],
    }
}

def __get_caller(depth=2):
    frm = inspect.stack()[depth]
    mod = inspect.getmodule(frm[0])
    assert mod.__name__.startswith('fluidasserts')
    caller = mod.__name__.split('.')[2]
    if caller in LANGUAGE_SPECS:
        return LANGUAGE_SPECS[caller]
    return None


def __get_match_lines(grammar, code_file):
    """Check grammar in file."""
    caller = __get_caller(3)
    with open(code_file) as file_fd:
        affected_lines = []
        counter = 1
        for line in file_fd.readlines():
            try:
                parser = ~Or(caller['line_comment'])
                parser.parseString(line)
            except ParseException:
                counter += 1
                continue
            try:
                grammar.parseString(line)
                affected_lines.append(counter)
            except ParseException:
                pass
            finally:
                counter += 1
    return affected_lines


def check_grammar(grammar, code_dest):
    """Check grammar in location."""
    assert os.path.exists(code_dest)
    caller = __get_caller()
    vulns = {}
    if os.path.isfile(code_dest):
        vulns[code_dest] = __get_match_lines(grammar, code_dest)
        return vulns

    for root, _, files in os.walk(code_dest):
        for code_file in files:
            full_path = os.path.join(root, code_file)
            if not full_path.split('.')[1] in caller['extensions']:
                continue
            vulns[full_path] = __get_match_lines(grammar, full_path)
    return vulns
