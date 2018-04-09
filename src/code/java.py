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
from pyparsing import CaselessKeyword, Word, Literal, Optional, alphas


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
    matches = code_helper.check_grammar(generic_exception, java_dest)
    for code_file, vulns in matches.items():
        if vulns:
            show_open('Code uses generic exceptions', details='File: {}, \
Lines: {}'.format(code_file, ",".join([str(x) for x in vulns])))
            result = True
        else:
            show_close('Code does not use generic exceptions',
                       details='File: {}'.format(code_file))
    return result
