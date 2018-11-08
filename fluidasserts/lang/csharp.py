# -*- coding: utf-8 -*-

"""This module allows to check ``C#`` code vulnerabilities."""

# standard imports
# None

# 3rd party imports
from pyparsing import (CaselessKeyword, Word, Literal, Optional, alphas, Or,
                       alphanums, Suppress, nestedExpr, cppStyleComment,
                       SkipTo)

# local imports
from fluidasserts.helper import lang
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track, level


LANGUAGE_SPECS = {
    'extensions': ['cs'],
    'block_comment_start': '/*',
    'block_comment_end': '*/',
    'line_comment': ['//']
}  # type: dict


def _get_block(file_lines, line) -> str:
    """
    Return a C# block of code beginning in line.

    :param file_lines: Lines of code
    :param line: First line of block
    """
    return "".join(file_lines[line - 1:])


@level('low')
@track
def has_generic_exceptions(csharp_dest: str) -> bool:
    """
    Search for generic exceptions in a C# source file or package.

    :param csharp_dest: Path to a C# source file or package.
    """
    tk_catch = CaselessKeyword('catch')
    tk_generic_exc = CaselessKeyword('exception')
    tk_type = Word(alphas)
    tk_object_name = Word(alphas)
    tk_object = Word(alphas)
    generic_exception = Optional(Literal('}')) + tk_catch + Literal('(') + \
        tk_generic_exc + Optional(Literal('(') + tk_type + Literal(')')) + \
        Optional(tk_object_name) + \
        Optional(Literal('(') + tk_object + Literal(')'))

    result = False
    try:
        matches = lang.check_grammar(generic_exception, csharp_dest,
                                     LANGUAGE_SPECS)
    except AssertionError:
        show_unknown('File does not exist',
                     details=dict(code_dest=csharp_dest))
        return False
    for code_file, vulns in matches.items():
        if vulns:
            show_open('Code uses generic exceptions',
                      details=dict(file=code_file,
                                   fingerprint=lang.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns]),
                                   total_vulns=len(vulns)))
            result = True
        else:
            show_close('Code does not use generic exceptions',
                       details=dict(file=code_file,
                                    fingerprint=lang.
                                    file_hash(code_file)))
    return result


@level('low')
@track
def swallows_exceptions(csharp_dest: str) -> bool:
    """
    Search for ``catch`` blocks that are empty or only have comments.

    See `REQ.161 <https://fluidattacks.com/web/es/rules/161/>`_.

    :param csharp_dest: Path to a C# source file or package.
    """
    tk_catch = CaselessKeyword('catch')
    tk_word = Word(alphas)
    parser_catch = (Optional(Literal('}')) + tk_catch + Literal('(') +
                    tk_word + Optional(Literal('(') + tk_word + Literal(')')) +
                    Optional(tk_word) + Literal(')'))
    empty_catch = (Suppress(parser_catch) +
                   nestedExpr(opener='{', closer='}')).ignore(cppStyleComment)

    result = False
    try:
        catches = lang.check_grammar(parser_catch, csharp_dest, LANGUAGE_SPECS)
    except AssertionError:
        show_unknown('File does not exist',
                     details=dict(code_dest=csharp_dest))
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
def has_switch_without_default(csharp_dest: str) -> bool:
    r"""
    Check if all ``switch``\ es have a ``default`` clause.

    See `REQ.161 <https://fluidattacks.com/web/es/rules/161/>`_.

    :param csharp_dest: Path to a C# source file or package.
    """
    tk_switch = CaselessKeyword('switch')
    tk_case = CaselessKeyword('case') + (Word(alphanums))
    tk_default = CaselessKeyword('default')
    tk_break = CaselessKeyword('break') + Literal(';')
    def_stmt = Or([Suppress(tk_case), tk_default]) + \
        Suppress(Literal(':') + SkipTo(tk_break, include=True))
    prsr_sw = tk_switch + nestedExpr()
    switch_head = tk_switch + nestedExpr() + Optional(Literal('{'))
    sw_wout_def = (Suppress(prsr_sw) +
                   nestedExpr(opener='{', closer='}',
                              content=def_stmt)).ignore(cppStyleComment)

    result = False
    try:
        switches = lang.check_grammar(switch_head, csharp_dest, LANGUAGE_SPECS)
    except AssertionError:
        show_unknown('File does not exist',
                     details=dict(code_dest=csharp_dest))
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
def has_insecure_randoms(csharp_dest: str) -> bool:
    """
    Check if code instantiates ``Random`` class.

    See `REQ.224 <https://fluidattacks.com/web/es/rules/224/>`_.

    :param csharp_dest: Path to a C# source file or package.
    """
    tk_class = CaselessKeyword('random')
    tk_variable = Word(alphanums)
    tk_new = CaselessKeyword('new')
    tk_params = nestedExpr()
    call_function = tk_class + tk_variable + Literal('=') + tk_new + \
        tk_class + Suppress(tk_params)

    result = False
    try:
        random_new = lang.check_grammar(call_function, csharp_dest,
                                        LANGUAGE_SPECS)
    except AssertionError:
        show_unknown('File does not exist',
                     details=dict(code_dest=csharp_dest))
        return False
    for code_file, vulns in random_new.items():
        if vulns:
            show_open('Code generates insecure random numbers',
                      details=dict(file=code_file,
                                   fingerprint=lang.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns]),
                                   total_vulns=len(vulns)))
            result = True
        else:
            show_close('Code does not generate insecure random numbers',
                       details=dict(file=code_file,
                                    fingerprint=lang.
                                    file_hash(code_file)))
    return result


@level('low')
@track
def has_if_without_else(csharp_dest: str) -> bool:
    r"""
    Check if all ``if``\ s have an ``else`` clause.

    See `REQ.161 <https://fluidattacks.com/web/es/rules/161/>`_.

    :param csharp_dest: Path to a C# source file or package.
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
        conds = lang.check_grammar(if_head, csharp_dest, LANGUAGE_SPECS)
    except AssertionError:
        show_unknown('File does not exist',
                     details=dict(code_dest=csharp_dest))
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


@level('medium')
@track
def uses_md5_hash(csharp_dest: str) -> bool:
    """
    Check if code uses MD5 as hashing algorithm.

    See `REQ.150 <https://fluidattacks.com/web/es/rules/150/>`_.

    :param csharp_dest: Path to a C# source file or package.
    """
    method = 'MD5.Create(), new MD5CryptoServiceProvider()'
    tk_md5 = CaselessKeyword('md5')
    tk_create = CaselessKeyword('create')
    tk_params = nestedExpr()
    fn_1 = tk_md5 + Literal('.') + tk_create + tk_params

    tk_new = CaselessKeyword('new')
    tk_md5cry = CaselessKeyword('MD5CryptoServiceProvider')
    tk_params = nestedExpr()
    fn_2 = tk_new + tk_md5cry + tk_params

    call_function = Or([fn_1, fn_2])

    result = False
    try:
        matches = lang.check_grammar(call_function, csharp_dest,
                                     LANGUAGE_SPECS)
    except AssertionError:
        show_unknown('File does not exist',
                     details=dict(code_dest=csharp_dest))
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
def uses_sha1_hash(csharp_dest: str) -> bool:
    """
    Check if code uses SHA1 as hashing algorithm.

    See `REQ.150 <https://fluidattacks.com/web/es/rules/150/>`_.

    :param csharp_dest: Path to a C# source file or package.
    """
    method = "new SHA1CryptoServiceProvider(), new SHA1Managed()"
    tk_new = CaselessKeyword('new')
    tk_sha1cry = CaselessKeyword('SHA1CryptoServiceProvider')
    tk_sha1man = CaselessKeyword('SHA1Managed')
    tk_params = nestedExpr()
    call_function = tk_new + Or([tk_sha1cry, tk_sha1man]) + tk_params

    result = False
    try:
        matches = lang.check_grammar(call_function, csharp_dest,
                                     LANGUAGE_SPECS)
    except AssertionError:
        show_unknown('File does not exist',
                     details=dict(code_dest=csharp_dest))
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
def uses_ecb_encryption_mode(csharp_dest: str) -> bool:
    """
    Check if code uses ECB as encryption mode.

    :param csharp_dest: Path to a C# source file or package.
    """
    method = "Mode = CipherMode.ECB"
    tk_eq = Literal('=')
    tk_obj = SkipTo(tk_eq)
    tk_cm = CaselessKeyword('ciphermode')
    tk_ecb = CaselessKeyword('ecb')
    call_function = tk_obj + tk_eq + tk_cm + Literal('.') + tk_ecb

    result = False
    try:
        matches = lang.check_grammar(call_function, csharp_dest,
                                     LANGUAGE_SPECS)
    except AssertionError:
        show_unknown('File does not exist',
                     details=dict(code_dest=csharp_dest))
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
def uses_debug_writeline(csharp_dest: str) -> bool:
    """
    Check if code uses Debug.WriteLine method.

    :param csharp_dest: Path to a C# source file or package.
    """
    method = "Debug.WriteLine"
    tk_debug = CaselessKeyword('debug')
    tk_wrilin = CaselessKeyword('writeline')
    call_function = tk_debug + Literal('.') + tk_wrilin

    result = False
    try:
        matches = lang.check_grammar(call_function, csharp_dest,
                                     LANGUAGE_SPECS)
    except AssertionError:
        show_unknown('File does not exist',
                     details=dict(code_dest=csharp_dest))
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
def uses_console_writeline(csharp_dest: str) -> bool:
    """
    Check if code uses Debug.WriteLine method.

    :param csharp_dest: Path to a C# source file or package.
    """
    method = "Console.WriteLine"
    tk_console = CaselessKeyword('console')
    tk_wrilin = CaselessKeyword('writeline')
    call_function = tk_console + Literal('.') + tk_wrilin

    result = False
    try:
        matches = lang.check_grammar(call_function, csharp_dest,
                                     LANGUAGE_SPECS)
    except AssertionError:
        show_unknown('File does not exist',
                     details=dict(code_dest=csharp_dest))
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
