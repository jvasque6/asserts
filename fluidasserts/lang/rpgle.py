# -*- coding: utf-8 -*-

"""This module allows to check RPGLE code vulnerabilities."""

# standard imports
# None

# 3rd party imports
from pyparsing import (CaselessKeyword, Keyword, Literal, Word, Optional,
                       NotAny, alphas, alphanums, nums, cppStyleComment,
                       MatchFirst)

# local imports
from fluidasserts.helper import lang
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.generic import get_sha256
from fluidasserts.utils.decorators import track, level, notify

LANGUAGE_SPECS = {
    'extensions': ('rpg', 'rpgle',),
    'block_comment_start': None,
    'block_comment_end': None,
    'line_comment': ('//', '*',),
}  # type: dict


def _get_block(file_lines, line) -> str:
    """
    Return a C# block of code beginning in line.

    :param file_lines: Lines of code
    :param line: First line of block
    """
    return "\n".join(file_lines[line - 1:])


@notify
@level('medium')
@track
def has_dos_dow_sqlcod(rpg_dest: str, exclude: list = None) -> bool:
    r"""
    Search for DoS for using ``DoW SQLCOD = <ZERO>``\ .

    :param rpg_dest: Path to a RPG source or directory.
    """
    tk_dow = CaselessKeyword('dow')
    tk_sqlcod = CaselessKeyword('sqlcod')
    tk_literal_zero = CaselessKeyword('*zeros')
    tk_zeros = MatchFirst([Literal('0'), tk_literal_zero])

    dos_dow_sqlcod = tk_dow + tk_sqlcod + Literal('=') + tk_zeros

    result = False
    try:
        matches = lang.check_grammar(dos_dow_sqlcod, rpg_dest, LANGUAGE_SPECS,
                                     exclude)
        if not matches:
            show_close('Code does not have DoS for using "DoW SQLCOD = 0"',
                       details=dict(code_dest=rpg_dest))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=rpg_dest))
        return False
    else:
        result = True
        show_open('Code has DoS for using "DoW SQLCOD = 0"',
                  details=dict(matched=matches,
                               total_vulns=len(matches)))
    return result


@notify
@level('low')
@track
def has_unitialized_vars(rpg_dest: str, exclude: list = None) -> bool:
    """
    Search for unitialized variables.

    :param rpg_dest: Path to a RPG source or directory.
    """
    tk_data = Keyword('D')
    tk_first = Word(alphas + "_", exact=1)
    tk_rest = Word(alphanums + "_")
    tk_vartype = Word(alphas, exact=1)
    tk_varlen = Word(nums) + Word(alphas, exact=1)
    tk_inz = CaselessKeyword('inz')
    tk_varname = tk_first + tk_rest

    unitialized = tk_data + tk_varname + Optional(tk_vartype) + \
        Optional(tk_varlen) + Optional(Word(nums)) + NotAny(tk_inz)

    result = False
    try:
        matches = lang.check_grammar(unitialized, rpg_dest, LANGUAGE_SPECS,
                                     exclude)
        if not matches:
            show_close('Code does not have unitialized variables',
                       details=dict(code_dest=rpg_dest))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=rpg_dest))
        return False
    else:
        result = True
        show_open('Code has unitialized variables',
                  details=dict(matched=matches,
                               total_vulns=len(matches)))
    return result


@notify
@level('low')
@track
def has_generic_exceptions(rpg_dest: str, exclude: list = None) -> bool:
    """
    Search for on-error empty.

    See `REQ. 161
    <https://fluidattacks.com/web/rules/161/>`_.

    :param rpg_dest: Path to a RPG source or directory.
    """
    tk_on = CaselessKeyword('on')
    tk_error = CaselessKeyword('error')
    tk_monitor = tk_on + Literal('-') + tk_error + Literal(';')

    result = False
    try:
        matches = lang.check_grammar(tk_monitor, rpg_dest, LANGUAGE_SPECS,
                                     exclude)
        if not matches:
            show_close('Code does not have empty monitors',
                       details=dict(code_dest=rpg_dest))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=rpg_dest))
        return False
    else:
        result = True
        show_open('Code has empty monitors',
                  details=dict(matched=matches,
                               total_vulns=len(matches)))
    return result


@notify
@level('low')
@track
def swallows_exceptions(rpg_dest: str, exclude: list = None) -> bool:
    """
    Search for on-error without code.

    See `REQ.075
    <https://fluidattacks.com/web/rules/075>`_.

    :param rpg_dest: Path to a RPG source or directory.
    """
    tk_on = CaselessKeyword('on')
    tk_error = CaselessKeyword('error')
    tk_code = Word(nums)
    tk_monitor = tk_on + Literal('-') + tk_error + Optional(tk_code) + \
        Literal(';')
    tk_end_mon = CaselessKeyword('endmon') + Literal(';')
    prs_sw = (tk_monitor + tk_end_mon).ignore(cppStyleComment)
    result = False
    try:
        matches = lang.check_grammar(tk_monitor, rpg_dest, LANGUAGE_SPECS,
                                     exclude)
        if not matches:
            show_unknown('Code does not have error handling',
                         details=dict(code_dest=rpg_dest))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=rpg_dest))
        return False
    vulns = {}
    for code_file, val in matches.items():
        vulns.update(lang.block_contains_grammar(prs_sw, code_file,
                                                 val['lines'],
                                                 _get_block))
    if vulns:
        show_open('Code swallows exceptions',
                  details=dict(matched=vulns,
                               total_vulns=len(vulns)))
        result = True
    else:
        show_close('Code does not swallow exceptions',
                   details=dict(file=rpg_dest,
                                fingerprint=get_sha256(rpg_dest)))
    return result
