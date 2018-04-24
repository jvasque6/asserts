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
                       alphanums, Suppress, nestedExpr, javaStyleComment)

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
                      details=dict(file=code_file,
                                   fingerprint=code_helper.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns])))
            result = True
        else:
            show_close('Code does not use generic exceptions',
                       details=dict(file=code_file,
                                    fingerprint=code_helper.
                                    file_hash(code_file)))
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
                      details=dict(file=code_file,
                                   fingerprint=code_helper.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns])))
            result = True
        else:
            show_close('Code does not use printStackTrace',
                       details=dict(file=code_file,
                                    fingerprint=code_helper.
                                    file_hash(code_file)))
    return result

@track
def has_empty_catches(java_dest):
    """Check if an error is saved in a log."""
    tk_catch = CaselessKeyword('catch')
    tk_word = Word(alphas)
    parser_catch = (Optional(Literal('}')) + tk_catch + Literal('(') + \
        tk_word + Optional(Literal('(') + tk_word + Literal(')')) + \
        tk_word + Literal(')'))
    empty_catch = (Suppress(parser_catch) + \
                   nestedExpr(opener='{', closer='}')).ignore(javaStyleComment)

    result = False
    catches = code_helper.check_grammar(parser_catch, java_dest,
                                        LANGUAGE_SPECS)

    for code_file, lines in catches.items():
        vulns = []
        with open(code_file) as code_f:
            file_lines = code_f.readlines()
            for line in lines:
                txt = "".join(file_lines[line-1:])
                exception_block = empty_catch.searchString(txt)[0]
                if not exception_block[0]:
                    vulns.append(line)

        if not vulns:
            show_close('Code does not has empty catches',
                       details=dict(file=code_file,
                                    fingerprint=code_helper.
                                    file_hash(code_file)))
        else:
            show_open('Code has empty catches',
                      details=dict(file=code_file,
                                   fingerprint=code_helper.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns])))
            result = True
    return result
