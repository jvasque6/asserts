# -*- coding: utf-8 -*-

"""
C# module.

This module allows to check C# code vulnerabilities
"""

# standard imports
# None

# 3rd party imports
from pyparsing import (CaselessKeyword, Word, Literal, Optional, alphas, Or,
                       alphanums, Suppress, nestedExpr, cppStyleComment,
                       SkipTo)

# local imports
from fluidasserts.helper import lang_helper
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track


LANGUAGE_SPECS = {
    'extensions': ['cs'],
    'block_comment_start': '/*',
    'block_comment_end': '*/',
    'line_comment': ['//'],
}  # type: dict


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
        tk_object_name + Optional(Literal('(') + tk_object + Literal(')'))

    result = False
    matches = lang_helper.check_grammar(generic_exception, csharp_dest,
                                        LANGUAGE_SPECS)
    for code_file, vulns in matches.items():
        if vulns:
            show_open('Code uses generic exceptions',
                      details=dict(file=code_file,
                                   fingerprint=lang_helper.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns])))
            result = True
        else:
            show_close('Code does not use generic exceptions',
                       details=dict(file=code_file,
                                    fingerprint=lang_helper.
                                    file_hash(code_file)))
    return result


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
                    tk_word + Literal(')'))
    empty_catch = (Suppress(parser_catch) +
                   nestedExpr(opener='{', closer='}')).ignore(cppStyleComment)

    result = False
    catches = lang_helper.check_grammar(parser_catch, csharp_dest,
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
    switches = lang_helper.check_grammar(switch_head, csharp_dest,
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
    random_new = lang_helper.check_grammar(call_function, csharp_dest,
                                           LANGUAGE_SPECS)

    for code_file, vulns in random_new.items():
        if vulns:
            show_open('Code generates insecure random numbers',
                      details=dict(file=code_file,
                                   fingerprint=lang_helper.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns])))
            result = True
        else:
            show_close('Code does not generates insecure random numbers',
                       details=dict(file=code_file,
                                    fingerprint=lang_helper.
                                    file_hash(code_file)))
    return result


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
    conds = lang_helper.check_grammar(if_head, csharp_dest, LANGUAGE_SPECS)

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

    result = lang_helper.uses_insecure_method(call_function, csharp_dest,
                                              LANGUAGE_SPECS, method)
    return result


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

    result = lang_helper.uses_insecure_method(call_function, csharp_dest,
                                              LANGUAGE_SPECS, method)
    return result
