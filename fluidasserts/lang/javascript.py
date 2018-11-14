# -*- coding: utf-8 -*-

"""This module allows to check JavaScript code vulnerabilities."""

# standard imports
# None

# 3rd party imports
from pyparsing import (CaselessKeyword, Literal, Suppress, Word, alphanums,
                       nestedExpr, cppStyleComment, Optional, Or, SkipTo)

# local imports
from fluidasserts.helper import lang
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track, level

LANGUAGE_SPECS = {
    'extensions': ['js', 'ts'],
    'block_comment_start': '/*',
    'block_comment_end': '*/',
    'line_comment': ['//']
}  # type: dict


def _get_block(file_lines, line) -> str:
    """
    Return a JavaScript block of code beginning in line.

    :param file_lines: Lines of code
    :param line: First line of block
    """
    return "".join(file_lines[line - 1:])


@level('low')
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
    result = False
    try:
        matches = lang.check_grammar(clog, js_dest, LANGUAGE_SPECS)
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=js_dest))
        return False
    for code_file, vulns in matches.items():
        if vulns:
            show_open('Code uses {} method'.format(method),
                      details=dict(file=code_file,
                                   fingerprint=lang.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns]),
                                   total_vulns=len(vulns)))
            result = True
        else:
            show_close('Code does not use {} method'.format(method),
                       details=dict(file=code_file,
                                    fingerprint=lang.
                                    file_hash(code_file)))
    return result


@level('medium')
@track
def uses_eval(js_dest: str) -> bool:
    """
    Search for ``eval()`` calls in a JavaScript file or directory.

    :param js_dest: Path to a JavaScript source file or directory.
    """
    method = 'eval()'
    tk_method = CaselessKeyword('eval')
    call_function = tk_method + Suppress(nestedExpr())
    result = False
    try:
        matches = lang.check_grammar(call_function, js_dest,
                                     LANGUAGE_SPECS)
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=js_dest))
        return False
    for code_file, vulns in matches.items():
        if vulns:
            show_open('Code uses {} method'.format(method),
                      details=dict(file=code_file,
                                   fingerprint=lang.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns]),
                                   total_vulns=len(vulns)))
            result = True
        else:
            show_close('Code does not use {} method'.format(method),
                       details=dict(file=code_file,
                                    fingerprint=lang.
                                    file_hash(code_file)))
    return result


@level('low')
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

    result = False
    try:
        matches = lang.check_grammar(lsto, js_dest, LANGUAGE_SPECS)
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=js_dest))
        return False
    for code_file, vulns in matches.items():
        if vulns:
            show_open('Code uses {} method'.format(method),
                      details=dict(file=code_file,
                                   fingerprint=lang.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns]),
                                   total_vulns=len(vulns)))
            result = True
        else:
            show_close('Code does not use {} method'.format(method),
                       details=dict(file=code_file,
                                    fingerprint=lang.
                                    file_hash(code_file)))
    return result


@level('low')
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

    result = False
    try:
        matches = lang.check_grammar(call_function, js_dest, LANGUAGE_SPECS)
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=js_dest))
        return False
    for code_file, vulns in matches.items():
        if vulns:
            show_open('Code uses {} method'.format(method),
                      details=dict(file=code_file,
                                   fingerprint=lang.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns]),
                                   total_vulns=len(vulns)))
            result = True
        else:
            show_close('Code does not use {} method'.format(method),
                       details=dict(file=code_file,
                                    fingerprint=lang.
                                    file_hash(code_file)))
    return result


@level('low')
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
    try:
        catches = lang.check_grammar(parser_catch, js_dest, LANGUAGE_SPECS)
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=js_dest))
        return False
    for code_file, lines in catches.items():
        vulns = lang.block_contains_empty_grammar(empty_catch,
                                                  code_file, lines,
                                                  _get_block)
        if not vulns:
            show_close('Code does not have empty catches',
                       details=dict(file=code_file,
                                    fingerprint=lang.
                                    file_hash(code_file)))
        else:
            show_open('Code has empty catches',
                      details=dict(file=code_file,
                                   fingerprint=lang.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns]),
                                   total_vulns=len(vulns)))
            result = True
    return result


@level('low')
@track
def has_switch_without_default(js_dest: str) -> bool:
    r"""
    Check if all ``switch``\ es have a ``default`` clause.

    See `REQ.161 <https://fluidattacks.com/web/es/rules/161/>`_.

    :param js_dest: Path to a JavaScript source file or package.
    """
    tk_switch = CaselessKeyword('switch')
    tk_case = CaselessKeyword('case') + SkipTo(Literal(':'))
    tk_default = CaselessKeyword('default') + Literal(':')
    tk_break = (CaselessKeyword('break') + Optional(Literal(';'))) | \
        Literal('}')
    def_stmt = Or([Suppress(tk_case), tk_default]) + \
        Suppress(SkipTo(tk_break, include=True))
    prsr_sw = tk_switch + nestedExpr()
    switch_head = tk_switch + nestedExpr() + Optional(Literal('{'))
    sw_wout_def = (Suppress(prsr_sw) +
                   nestedExpr(opener='{', closer='}',
                              content=def_stmt)).ignore(cppStyleComment)

    result = False
    try:
        switches = lang.check_grammar(switch_head, js_dest, LANGUAGE_SPECS)
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=js_dest))
        return False
    for code_file, lines in switches.items():
        vulns = lang.block_contains_empty_grammar(sw_wout_def,
                                                  code_file, lines,
                                                  _get_block)
        if not vulns:
            show_close('Code has switch with default clause',
                       details=dict(file=code_file,
                                    fingerprint=lang.
                                    file_hash(code_file)))
        else:
            show_open('Code does not have switch with default clause',
                      details=dict(file=code_file,
                                   fingerprint=lang.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns]),
                                   total_vulns=len(vulns)))
            result = True
    return result


@level('low')
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
    try:
        conds = lang.check_grammar(if_head, js_dest, LANGUAGE_SPECS)
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=js_dest))
        return False
    for code_file, lines in conds.items():
        vulns = lang.block_contains_empty_grammar(if_wout_else,
                                                  code_file, lines,
                                                  _get_block)
        if not vulns:
            show_close('Code has if with else clause',
                       details=dict(file=code_file,
                                    fingerprint=lang.
                                    file_hash(code_file)))
        else:
            show_open('Code does not have if with else clause',
                      details=dict(file=code_file,
                                   fingerprint=lang.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns]),
                                   total_vulns=len(vulns)))
            result = True
    return result
