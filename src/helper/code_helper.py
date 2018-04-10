# -*- coding: utf-8 -*-

"""Code helper.

This module has helper functions for code modules
"""

# standard imports
import os

# 3rd party imports
# None

# local imports
from pyparsing import Or, ParseException


def __get_match_lines(grammar, code_file, lang_spec):
    """Check grammar in file."""
    with open(code_file) as file_fd:
        affected_lines = []
        counter = 1
        for line in file_fd.readlines():
            try:
                parser = ~Or(lang_spec['line_comment'])
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


def check_grammar(grammar, code_dest, lang_spec):
    """Check grammar in location."""
    assert os.path.exists(code_dest)
    vulns = {}
    if os.path.isfile(code_dest):
        vulns[code_dest] = __get_match_lines(grammar, code_dest, lang_spec)
        return vulns

    for root, _, files in os.walk(code_dest):
        for code_file in files:
            full_path = os.path.join(root, code_file)
            if not full_path.split('.')[1] in lang_spec['extensions']:
                continue
            vulns[full_path] = __get_match_lines(grammar, full_path, lang_spec)
    return vulns
