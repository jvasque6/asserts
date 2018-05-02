# -*- coding: utf-8 -*-

"""
Java module.

This module allows to check Java code vulnerabilities
"""

# standard imports
# None

# 3rd party imports
from pyparsing import (CaselessKeyword, Word, Literal, Optional, alphas, Or,
                       alphanums, Suppress, nestedExpr, javaStyleComment,
                       SkipTo)

# local imports
from fluidasserts.helper import code_helper
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track


LANGUAGE_SPECS = {
    'extensions': ['java'],
    'block_comment_start': '/*',
    'block_comment_end': '*/',
    'line_comment': ['//'],
}

@track
def has_generic_exceptions(java_dest):
    """
    Search for generic exceptions in a Java source file or package.

    :param java_dest: Path to a Java source file or package.
    :rtype: bool
    """
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
    """
    Search for ``printStackTrace`` calls in a  or package.

    :param java_dest: Path to a Java source file or package.
    :rtype: bool
    """
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
    """
    Search for ``catch`` blocks that are empty or only have comments.

    See `REQ.161 <https://fluidattacks.com/web/es/rules/161/>`_.

    :param java_dest: Path to a Java source file or package.
    :rtype: bool
    """
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
        vulns = code_helper.block_contains_empty_grammar(empty_catch,
                                                         code_file, lines)
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

@track
def has_switch_without_default(java_dest):
    r"""
    Check if all ``switch``\ es have a ``default`` clause.

    See `REQ.161 <https://fluidattacks.com/web/es/rules/161/>`_.

    :param java_dest: Path to a Java source file or package.
    :rtype: bool
    """
    tk_switch = CaselessKeyword('switch')
    tk_case = CaselessKeyword('case') + (Word(alphanums))
    tk_default = CaselessKeyword('default')
    tk_break = CaselessKeyword('break') + Literal(';')
    def_stmt = Or([Suppress(tk_case), tk_default]) + \
               Suppress(Literal(':') + SkipTo(tk_break, include=True))
    prsr_sw = tk_switch + nestedExpr()
    switch_head = tk_switch + nestedExpr() + Optional(Literal('{'))
    sw_wout_def = (Suppress(prsr_sw) + \
                  nestedExpr(opener='{', closer='}',
                             content=def_stmt)).ignore(javaStyleComment)

    result = False
    switches = code_helper.check_grammar(switch_head, java_dest,
                                         LANGUAGE_SPECS)

    for code_file, lines in switches.items():
        vulns = code_helper.block_contains_empty_grammar(sw_wout_def,
                                                         code_file, lines)
        if not vulns:
            show_close('Code has switch with default clause',
                       details=dict(file=code_file,
                                    fingerprint=code_helper.
                                    file_hash(code_file)))
        else:
            show_open('Code does not has switch with default clause',
                      details=dict(file=code_file,
                                   fingerprint=code_helper.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns])))
            result = True
    return result
