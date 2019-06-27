# -*- coding: utf-8 -*-

"""This module allows to check JavaScript code vulnerabilities."""

# standard imports
import re

# 3rd party imports
from pyparsing import (CaselessKeyword, Literal, Suppress, Word, alphanums,
                       nestedExpr, cppStyleComment, Optional,
                       MatchFirst, Keyword, Empty, QuotedString)

# local imports
from fluidasserts.helper import lang
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track, level, notify

LANGUAGE_SPECS = {
    'extensions': ('js', 'ts',),
    'block_comment_start': '/*',
    'block_comment_end': '*/',
    'line_comment': ('//',)
}  # type: dict


# 'anything'
L_CHAR = QuotedString("'")
# "anything"
L_STRING = QuotedString('"')

# Compiled regular expressions
RE_HAVES_DEFAULT = re.compile(r'(?:default\s*:)', flags=re.M)


def _get_block(file_lines, line) -> str:
    """
    Return a JavaScript block of code beginning in line.

    :param file_lines: Lines of code
    :param line: First line of block
    """
    return "".join(file_lines[line - 1:])


@notify
@level('low')
@track
def uses_console_log(js_dest: str, exclude: list = None) -> bool:
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
        matches = lang.check_grammar(clog, js_dest, LANGUAGE_SPECS, exclude)
        if not matches:
            show_close('Code does not use {} method'.format(method),
                       details=dict(code_dest=js_dest))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=js_dest))
        return False
    else:
        result = True
        show_open('Code uses {} method'.format(method),
                  details=dict(matched=matches,
                               total_vulns=len(matches)))
    return result


@notify
@level('medium')
@track
def uses_eval(js_dest: str, exclude: list = None) -> bool:
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
                                     LANGUAGE_SPECS, exclude)
        if not matches:
            show_close('Code does not use {} method'.format(method),
                       details=dict(code_dest=js_dest))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=js_dest))
        return False
    else:
        result = True
        show_open('Code uses {} method'.format(method),
                  details=dict(matched=matches,
                               total_vulns=len(matches)))
    return result


@notify
@level('low')
@track
def uses_localstorage(js_dest: str, exclude: list = None) -> bool:
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
        matches = lang.check_grammar(lsto, js_dest, LANGUAGE_SPECS, exclude)
        if not matches:
            show_close('Code does not use {} method'.format(method),
                       details=dict(code_dest=js_dest))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=js_dest))
        return False
    else:
        result = True
        show_open('Code uses {} method'.format(method),
                  details=dict(matched=matches,
                               total_vulns=len(matches)))
    return result


@notify
@level('low')
@track
def has_insecure_randoms(js_dest: str, exclude: list = None) -> bool:
    r"""
    Check if code uses ``Math.Random()``\ .

    See `REQ.224 <https://fluidattacks.com/web/rules/224/>`_.

    :param js_dest: Path to a JavaScript source file or package.
    """
    method = 'Math.random()'
    tk_class = CaselessKeyword('math')
    tk_method = CaselessKeyword('random')
    tk_params = nestedExpr()
    call_function = tk_class + Literal('.') + tk_method + Suppress(tk_params)

    result = False
    try:
        matches = lang.check_grammar(call_function, js_dest, LANGUAGE_SPECS,
                                     exclude)
        if not matches:
            show_close('Code does not use {} method'.format(method),
                       details=dict(code_dest=js_dest))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=js_dest))
        return False
    else:
        result = True
        show_open('Code uses {} method'.format(method),
                  details=dict(matched=matches,
                               total_vulns=len(matches)))
    return result


@notify
@level('low')
@track
def swallows_exceptions(js_dest: str, exclude: list = None) -> bool:
    """
    Search for ``catch`` blocks that are empty or only have comments.

    See `REQ.161 <https://fluidattacks.com/web/rules/161/>`_.

    See `CWE-391 <https://cwe.mitre.org/data/definitions/391.html>`_.

    :param js_dest: Path to a JavaScript source file or package.
    """
    # Empty() grammar matches 'anything'
    # ~Empty() grammar matches 'not anything' or 'nothing'
    classic = Suppress(Keyword('catch')) + nestedExpr(opener='(', closer=')') \
        + nestedExpr(opener='{', closer='}', content=~Empty())

    modern = Suppress('.' + Keyword('catch')) + nestedExpr(
        opener='(', closer=')', content=~Empty())

    grammar = MatchFirst([classic, modern])
    grammar.ignore(cppStyleComment)

    try:
        matches = lang.path_contains_grammar(grammar, js_dest,
                                             LANGUAGE_SPECS, exclude)
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=js_dest))
    else:
        if matches:
            show_open('Code has empty "catch" blocks',
                      details=dict(matched=matches))
            return True
        show_close('Code does not have empty "catch" blocks',
                   details=dict(code_dest=js_dest))
    return False


@notify
@level('low')
@track
def has_switch_without_default(js_dest: str, exclude: list = None) -> bool:
    r"""
    Check if all ``switch``\ es have a ``default`` clause.

    See `REQ.161 <https://fluidattacks.com/web/rules/161/>`_.

    See `CWE-478 <https://cwe.mitre.org/data/definitions/478.html>`_.

    :param js_dest: Path to a JavaScript source file or package.
    """
    switch = Keyword('switch') + nestedExpr(opener='(', closer=')')
    switch_block = Suppress(switch) + nestedExpr(opener='{', closer='}')
    switch_block.ignore(cppStyleComment)
    switch_block.ignore(L_CHAR)
    switch_block.ignore(L_STRING)
    switch_block.addCondition(lambda x: not RE_HAVES_DEFAULT.search(str(x)))
    try:
        matches = lang.path_contains_grammar(switch_block, js_dest,
                                             LANGUAGE_SPECS, exclude)
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=js_dest))
        return False
    if matches:
        show_open('Code does not have "switch" with "default" clause',
                  details=dict(matched=matches))
        return True
    show_close('Code has "switch" with "default" clause',
               details=dict(code_dest=js_dest))
    return False


@notify
@level('low')
@track
def has_if_without_else(js_dest: str, exclude: list = None) -> bool:
    r"""
    Check if all ``if``\ s have an ``else`` clause.

    See `REQ.161 <https://fluidattacks.com/web/rules/161/>`_.

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
        conds = lang.check_grammar(if_head, js_dest, LANGUAGE_SPECS, exclude)
        if not conds:
            show_close('Code does not have conditionals',
                       details=dict(code_dest=js_dest))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=js_dest))
        return False
    vulns = {}
    for code_file, val in conds.items():
        vulns.update(lang.block_contains_empty_grammar(if_wout_else,
                                                       code_file, val['lines'],
                                                       _get_block))
    if not vulns:
        show_close('Code has "if" with "else" clauses',
                   details=dict(file=js_dest,
                                fingerprint=lang.
                                file_hash(js_dest)))
    else:
        show_open('Code does not have "if" with "else" clause',
                  details=dict(matched=vulns,
                               total_vulns=len(vulns)))
        result = True
    return result
