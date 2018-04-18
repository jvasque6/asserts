# -*- coding: utf-8 -*-

"""Java module.

This module allows to check Java code vulnerabilities
"""

# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts.helper import code_helper
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track
from pyparsing import (CaselessKeyword, Word, Literal, Optional, alphas,
                       alphanums)

LANGUAGE_SPECS = {
    'extensions': ['java'],
    'block_comment_start': '/*',
    'block_comment_end': '*/',
    'line_comment': ['//'],
}

@track
def has_generic_exceptions(java_dest):
    """Search generic exceptions in file or dir."""
    tk_catch = CaselessKeyword('catch')
    tk_generic_exc = CaselessKeyword('exception')
    tk_type = Word(alphas)
    tk_object_name = Word(alphas)
    tk_object = Word(alphas)
    generic_exception = Optional(Literal('}')) + tk_catch + Literal('(') + \
        tk_generic_exc + Optional(Literal('(') + tk_type + Literal(')')) + \
        tk_object_name + Optional(Literal('(') + tk_object + Literal(')'))

    result = False
    matches = code_helper.check_grammar(generic_exception, java_dest,
                                        LANGUAGE_SPECS)
    for code_file, vulns in matches.items():
        if vulns:
            show_open('Code uses generic exceptions',
                      details=dict(file=code_file, lines=vulns))
            result = True
        else:
            show_close('Code does not use generic exceptions',
                       details=dict(file=code_file))
    return result


@track
def uses_print_stack_trace(java_dest):
    """Search printStackTrace calls."""
    tk_object = Word(alphanums)
    tk_pst = CaselessKeyword('printstacktrace')

    pst = tk_object + Literal('.') + tk_pst + Literal('(') + Literal(')')

    result = False
    matches = code_helper.check_grammar(pst, java_dest, LANGUAGE_SPECS)
    for code_file, vulns in matches.items():
        if vulns:
            show_open('Code uses printStackTrace',
                      details=dict(file=code_file, lines=vulns))
            result = True
        else:
            show_close('Code does not use printStackTrace',
                       details=dict(file=code_file))
    return result
