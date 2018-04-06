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

# Java grammar
CATCH = CaselessKeyword('catch')
GENERIC_EXC = CaselessKeyword('exception')
TYPE = Word(alphas)
OBJECT_NAME = Word(alphas)
OBJECT = Word(alphas)
GENERIC_EXCEPTION = CATCH + Literal('(') + GENERIC_EXC + \
    Optional(Literal('(') + TYPE + Literal(')')) + OBJECT_NAME + \
    Optional(Literal('(') + OBJECT + Literal(')'))

@track
def has_generic_exceptions(java_file):
    """Search if code uses generic exceptions."""
    with open(java_file) as file_fd:
        affected_lines = []
        counter = 1
        for line in file_fd.readlines():
            try:
                GENERIC_EXCEPTION.parseString(line)
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
