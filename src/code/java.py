# -*- coding: utf-8 -*-

"""Java module.

This module allows to check Java code vulnerabilities
"""

# standard imports
import os

# 3rd party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track
from pyparsing import (ParseException, CaselessKeyword, Word, Literal,
                       Optional, alphas)


def __generic_exceptions_grammar(java_file):
    """Java grammar for generic exceptions."""
    # Generic exception grammar
    kw_catch = CaselessKeyword('catch')
    kw_generic_exc = CaselessKeyword('exception')
    kw_type = Word(alphas)
    kw_object_name = Word(alphas)
    kw_object = Word(alphas)
    generic_exception = kw_catch + Literal('(') + kw_generic_exc + \
        Optional(Literal('(') + kw_type + Literal(')')) + kw_object_name + \
        Optional(Literal('(') + kw_object + Literal(')'))

    with open(java_file) as file_fd:
        affected_lines = []
        counter = 1
        for line in file_fd.readlines():
            try:
                generic_exception.parseString(line)
                affected_lines.append(counter)
            except ParseException:
                pass
            finally:
                counter += 1
    return affected_lines


@track
def has_generic_exceptions(java_dest):
    """Search generic exceptions in file or dir."""
    assert os.path.exists(java_dest)
    if os.path.isfile(java_dest):
        result = __generic_exceptions_grammar(java_dest)
        if result:
            show_open('Code uses generic exceptions', details='File: {}, \
Lines: {}'.format(java_dest, ",".join([str(x) for x in result])))
            return True
        show_close('Code does not use generic exceptions',
                   details='File: {}'.format(java_dest))
        return False
    result = False
    for root, _, files in os.walk(java_dest):
        for java_file in files:
            full_path = os.path.join(root, java_file)
            if not full_path.lower().endswith('.java'):
                continue
            vulns = __generic_exceptions_grammar(full_path)
            if vulns:
                show_open('Code uses generic exceptions', details='File: {}, \
Lines: {}'.format(full_path, ",".join([str(x) for x in vulns])))
                result = True
            else:
                show_close('Code does not use generic exceptions',
                           details='File: {}'.format(full_path))
    return result
