# -*- coding: utf-8 -*-

"""
JavaScript module.

This module allows to check JavaScript code vulnerabilities.
"""

# standard imports
# None

# 3rd party imports
from pyparsing import (CaselessKeyword, Literal, Suppress, Word, alphanums,
                       nestedExpr, cppStyleComment, Optional, Or, SkipTo)

# local imports
from fluidasserts.helper import lang_helper
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track

LANGUAGE_SPECS = {
    'extensions': ['js', 'ts'],
    'block_comment_start': '/*',
    'block_comment_end': '*/',
    'line_comment': ['//'],
}


@track
def uses_console_log(js_dest: str) -> bool:
    """
    Search for ``console.log()`` calls in a JavaScript file or directory.

    :param js_dest: Path to a JavaScript source file or directory.
    """
    method = 'Console.log()'
    tk_object = CaselessKeyword('console')
    tk_method = CaselessKeyword('log')

    clog = tk_object + Literal('.') + tk_method + Suppress(nestedExpr())
    result = lang_helper.uses_insecure_method(clog, js_dest,
                                              LANGUAGE_SPECS, method)
    return result


@track
def uses_eval(js_dest):
    """
    Search for ``eval()`` calls in a JavaScript file or directory.

    :param js_dest: Path to a JavaScript source file or directory.
    :rtype: bool
    """
    method = 'eval()'
    tk_method = CaselessKeyword('eval')
    call_function = tk_method + Suppress(nestedExpr())
    result = lang_helper.uses_insecure_method(call_function, js_dest,
                                              LANGUAGE_SPECS, method)
    return result


@track
def uses_localstorage(js_dest: str) -> bool:
    """
    Search for ``localStorage`` calls in a JavaScript source file or directory.

    :param js_dest: Path to a JavaScript source file or directory.
    """
    method = 'window.localStorage'
    tk_object = CaselessKeyword('localstorage')
    tk_method = Word(alphanums)

    lsto = tk_object + Literal('.') + tk_method + Suppress(nestedExpr())

    result = lang_helper.uses_insecure_method(lsto, js_dest,
                                              LANGUAGE_SPECS, method)
    return result


@track
def has_insecure_randoms(js_dest: str) -> bool:
    r"""
    Check if code uses ``Math.Random()``\ .

    See `REQ.224 <https://fluidattacks.com/web/es/rules/224/>`_.

    :param js_dest: Path to a JavaScript source file or package.
    """
    method = 'Math.random()'
    tk_class = CaselessKeyword('math')
    tk_method = CaselessKeyword('random')
    tk_params = nestedExpr()
    call_function = tk_class + Literal('.') + tk_method + Suppress(tk_params)

    result = lang_helper.uses_insecure_method(call_function, js_dest,
                                              LANGUAGE_SPECS, method)
    return result


@track
def swallows_exceptions(js_dest: str) -> bool:
    """
    Search for ``catch`` blocks that are empty or only have comments.

    See `REQ.161 <https://fluidattacks.com/web/es/rules/161/>`_.

    :param js_dest: Path to a JavaScript source file or package.
    """
    tk_catch = CaselessKeyword('catch')
    parser_catch = (Optional(Literal('}')) + tk_catch + nestedExpr())
    empty_catch = (Suppress(parser_catch) +
                   nestedExpr(opener='{', closer='}')).ignore(cppStyleComment)

    result = False
    catches = lang_helper.check_grammar(parser_catch, js_dest,
                                        LANGUAGE_SPECS)

    for code_file, lines in catches.items():
        vulns = lang_helper.block_contains_empty_grammar(empty_catch,
                                                         code_file, lines)
        if not vulns:
            show_close('Code does not has empty catches',
                       details=dict(file=code_file,
                                    fingerprint=lang_helper.
                                    file_hash(code_file)))
        else:
            show_open('Code has empty catches',
                      details=dict(file=code_file,
                                   fingerprint=lang_helper.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns])))
            result = True
    return result


@track
def has_switch_without_default(js_dest: str) -> bool:
    r"""
    Check if all ``switch``\ es have a ``default`` clause.

    See `REQ.161 <https://fluidattacks.com/web/es/rules/161/>`_.

    :param js_dest: Path to a JavaScript source file or package.
    """
    tk_switch = CaselessKeyword('switch')
    tk_case = CaselessKeyword('case') + (Word(alphanums))
    tk_default = CaselessKeyword('default')
    tk_break = (CaselessKeyword('break') + Optional(Literal(';'))) | \
        Literal('}')
    def_stmt = Or([Suppress(tk_case), tk_default]) + \
        Suppress(Literal(':') + SkipTo(tk_break, include=True))
    prsr_sw = tk_switch + nestedExpr()
    switch_head = tk_switch + nestedExpr() + Optional(Literal('{'))
    sw_wout_def = (Suppress(prsr_sw) +
                   nestedExpr(opener='{', closer='}',
                              content=def_stmt)).ignore(cppStyleComment)

    result = False
    switches = lang_helper.check_grammar(switch_head, js_dest,
                                         LANGUAGE_SPECS)

    for code_file, lines in switches.items():
        vulns = lang_helper.block_contains_empty_grammar(sw_wout_def,
                                                         code_file, lines)
        if not vulns:
            show_close('Code has switch with default clause',
                       details=dict(file=code_file,
                                    fingerprint=lang_helper.
                                    file_hash(code_file)))
        else:
            show_open('Code does not has switch with default clause',
                      details=dict(file=code_file,
                                   fingerprint=lang_helper.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns])))
            result = True
    return result


@track
def has_if_without_else(js_dest: str) -> bool:
    r"""
    Check if all ``if``\ s have an ``else`` clause.

    See `REQ.161 <https://fluidattacks.com/web/es/rules/161/>`_.

    :param js_dest: Path to a JavaScript source file or package.
    """
    tk_if = CaselessKeyword('if')
    tk_else = CaselessKeyword('else')
    block = nestedExpr(opener='{', closer='}')
    prsr_if = tk_if + nestedExpr() + block
    prsr_else = Suppress(tk_else) + (prsr_if | block)
    if_head = tk_if + nestedExpr() + Optional(Literal('{'))
    if_wout_else = (Suppress(prsr_if) + prsr_else).ignore(cppStyleComment)

    result = False
    conds = lang_helper.check_grammar(if_head, js_dest, LANGUAGE_SPECS)

    for code_file, lines in conds.items():
        vulns = lang_helper.block_contains_empty_grammar(if_wout_else,
                                                         code_file, lines)
        if not vulns:
            show_close('Code has if with else clause',
                       details=dict(file=code_file,
                                    fingerprint=lang_helper.
                                    file_hash(code_file)))
        else:
            show_open('Code does not has if with else clause',
                      details=dict(file=code_file,
                                   fingerprint=lang_helper.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns])))
            result = True
    return result