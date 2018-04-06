# -*- coding: utf-8 -*-

"""Java module.

This module allows to check Java code vulnerabilities
"""

# standard imports
# None
# 3rd party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track
from pyparsing import (ParseException, CaselessKeyword, Word, Literal,
                       Optional, alphas)


@track
def has_generic_exceptions(java_file):
    """Search if code uses generic exceptions."""
# Java grammar
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
        if affected_lines:
            show_open('Code uses generic exceptions', details='File: {}, \
Lines: {}'.format(java_file, ",".join([str(x) for x in affected_lines])))
            return True
        show_close('Code does not use generic exceptions',
                   details='File: {}'.format(java_file))
        return False
