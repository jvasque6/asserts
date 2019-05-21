# -*- coding: utf-8 -*-

"""This module allows to check Java code vulnerabilities."""

# standard imports
# None

# 3rd party imports
from pyparsing import (CaselessKeyword, Word, Literal, Optional, alphas, Or,
                       alphanums, Suppress, nestedExpr, javaStyleComment,
                       SkipTo, QuotedString, oneOf, Keyword, MatchFirst)

# local imports
from fluidasserts.helper import lang
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track, level


LANGUAGE_SPECS = {
    'extensions': ['java'],
    'block_comment_start': '/*',
    'block_comment_end': '*/',
    'line_comment': ['//']
}  # type: dict


def _get_block(file_lines, line) -> str:
    """
    Return a Java block of code beginning in line.

    :param file_lines: Lines of code
    :param line: First line of block
    """
    return "".join(file_lines[line - 1:])


@level('low')
@track
def has_generic_exceptions(java_dest: str, exclude: list = None) -> bool:
    """
    Search for generic exceptions in a Java source file or package.

    :param java_dest: Path to a Java source file or package.
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
    try:
        matches = lang.check_grammar(generic_exception, java_dest,
                                     LANGUAGE_SPECS, exclude)
        if not matches:
            show_unknown('Not files matched',
                         details=dict(code_dest=java_dest))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=java_dest))
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
def uses_print_stack_trace(java_dest: str, exclude: list = None) -> bool:
    """
    Search for ``printStackTrace`` calls in a  or package.

    :param java_dest: Path to a Java source file or package.
    """
    method = 'exc.printStackTrace()'
    tk_object = Word(alphanums)
    tk_pst = CaselessKeyword('printstacktrace')
    pst = tk_object + Literal('.') + tk_pst + Literal('(') + Literal(')')

    result = False
    try:
        matches = lang.check_grammar(pst, java_dest, LANGUAGE_SPECS, exclude)
        if not matches:
            show_unknown('Not files matched',
                         details=dict(code_dest=java_dest))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=java_dest))
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
def swallows_exceptions(java_dest: str, exclude: list = None) -> bool:
    """
    Search for ``catch`` blocks that are empty or only have comments.

    See `REQ.161 <https://fluidattacks.com/web/en/rules/161/>`_.

    :param java_dest: Path to a Java source file or package.
    """
    tk_catch = CaselessKeyword('catch')
    tk_word = Word(alphas)
    parser_catch = (Optional(Literal('}')) + tk_catch + Literal('(') +
                    tk_word + Optional(Literal('(') + tk_word + Literal(')')) +
                    tk_word + Literal(')'))
    empty_catch = (Suppress(parser_catch) +
                   nestedExpr(opener='{', closer='}')).ignore(javaStyleComment)

    result = False
    try:
        catches = lang.check_grammar(parser_catch, java_dest, LANGUAGE_SPECS,
                                     exclude)
        if not catches:
            show_unknown('Not files matched',
                         details=dict(code_dest=java_dest))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=java_dest))
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
def has_switch_without_default(java_dest: str, exclude: list = None) -> bool:
    r"""
    Check if all ``switch``\ es have a ``default`` clause.

    See `REQ.161 <https://fluidattacks.com/web/en/rules/161/>`_.

    :param java_dest: Path to a Java source file or package.
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
                              content=def_stmt)).ignore(javaStyleComment)

    result = False
    try:
        switches = lang.check_grammar(switch_head, java_dest, LANGUAGE_SPECS,
                                      exclude)
        if not switches:
            show_unknown('Not files matched',
                         details=dict(code_dest=java_dest))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=java_dest))
        return False
    for code_file, lines in switches.items():
        vulns = lang.block_contains_empty_grammar(sw_wout_def,
                                                  code_file, lines,
                                                  _get_block)
        if not vulns:
            show_close('Code has "switch" with "default" clause',
                       details=dict(file=code_file,
                                    fingerprint=lang.
                                    file_hash(code_file)))
        else:
            show_open('Code does not have "switch" with "default" clause',
                      details=dict(file=code_file,
                                   fingerprint=lang.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns]),
                                   total_vulns=len(vulns)))
            result = True
    return result


@level('low')
@track
def has_insecure_randoms(java_dest: str, exclude: list = None) -> bool:
    r"""
    Check if code uses insecure random generators.

    - ``java.util.Random()``.
    - ``java.lang.Math.random()``.

    See `REQ.224 <https://fluidattacks.com/web/en/rules/224/>`_.

    :param java_dest: Path to a Java source file or package.
    """
    tk_dot = Literal('.')
    tk_new = Keyword('new')
    tk_math = Keyword('Math')
    tk_equal = Literal('=')
    tk_params = Suppress(nestedExpr())
    tk_random = CaselessKeyword('random')
    tk_javavar = Word(alphas + '$_', alphanums + '_')
    insecure_methods = 'java.util.Random() or java.lang.Math.random()'
    insecure_randoms = [
        tk_random + tk_javavar + tk_equal + tk_new + tk_random + tk_params,
        tk_math + tk_dot + tk_random + tk_params,
    ]

    result = False
    try:
        matches = lang.check_grammar(
            MatchFirst(insecure_randoms), java_dest, LANGUAGE_SPECS, exclude)
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=java_dest))
        return False
    if not matches:
        show_unknown('Not files matched', details=dict(code_dest=java_dest))
        return False
    for code_file, vulns in matches.items():
        if vulns:
            show_open('Code uses {} method'.format(insecure_methods),
                      details=dict(file=code_file,
                                   fingerprint=lang.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns]),
                                   total_vulns=len(vulns)))
            result = True
        else:
            show_close('Code does not use {} method'.format(insecure_methods),
                       details=dict(file=code_file,
                                    fingerprint=lang.
                                    file_hash(code_file)))
    return result


@level('low')
@track
def has_if_without_else(java_dest: str, exclude: list = None) -> bool:
    r"""
    Check if all ``if``\ s have an ``else`` clause.

    See `REQ.161 <https://fluidattacks.com/web/en/rules/161/>`_.

    :param java_dest: Path to a Java source file or package.
    """
    tk_if = CaselessKeyword('if')
    tk_else = CaselessKeyword('else')
    block = nestedExpr(opener='{', closer='}')
    prsr_if = tk_if + nestedExpr() + block
    prsr_else = Suppress(tk_else) + (prsr_if | block)
    if_head = tk_if + nestedExpr() + Optional(Literal('{'))
    if_wout_else = (Suppress(prsr_if) + prsr_else).ignore(javaStyleComment)

    result = False
    try:
        conds = lang.check_grammar(if_head, java_dest, LANGUAGE_SPECS, exclude)
        if not conds:
            show_unknown('Not files matched',
                         details=dict(code_dest=java_dest))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=java_dest))
        return False
    for code_file, lines in conds.items():
        vulns = lang.block_contains_empty_grammar(if_wout_else,
                                                  code_file, lines,
                                                  _get_block)
        if not vulns:
            show_close('Code has "if" with "else" clauses',
                       details=dict(file=code_file,
                                    fingerprint=lang.
                                    file_hash(code_file)))
        else:
            show_open('Code does not have "if" with "else" clauses',
                      details=dict(file=code_file,
                                   fingerprint=lang.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns]),
                                   total_vulns=len(vulns)))
            result = True
    return result


@level('medium')
@track
def uses_insecure_cipher(java_dest: str, algorithm: str,
                         exclude: list = None) -> bool:
    """
    Check if code uses an insecure cipher algorithm.

    See `REQ.148 <https://fluidattacks.com/web/en/rules/148/>`_.
    See `REQ.149 <https://fluidattacks.com/web/en/rules/149/>`_.

    :param java_dest: Path to a Java source file or package.
    :param algorithm: Insecure algorithm.
    """
    method = 'Cipher.getInstance("{}")'.format(algorithm.upper())
    tk_algo = CaselessKeyword(algorithm)
    tk_mode = Literal('/') + oneOf('CBC ECB', caseless=True)
    tk_padd = Literal('/') + oneOf('NoPadding PKCS5Padding', caseless=True)
    tk_method = CaselessKeyword('cipher') + \
        Literal('.') + CaselessKeyword('getinstance')
    tk_arguments = Literal('"') + tk_algo + \
        Optional(tk_mode + Optional(tk_padd)) + Literal('"')
    instance = tk_method + Literal('(') + tk_arguments + Literal(')')

    result = False
    try:
        matches = lang.check_grammar(instance, java_dest, LANGUAGE_SPECS,
                                     exclude)
        if not matches:
            show_unknown('Not files matched',
                         details=dict(code_dest=java_dest))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=java_dest))
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
def uses_insecure_hash(java_dest: str, algorithm: str,
                       exclude: list = None) -> bool:
    """
    Check if code uses an insecure hashing algorithm.

    See `REQ.150 <https://fluidattacks.com/web/en/rules/150/>`_.

    :param java_dest: Path to a Java source file or package.
    :param algorithm: Insecure algorithm.
    """
    method = 'MessageDigest.getInstance("{}")'.format(algorithm.upper())
    tk_mess_dig = CaselessKeyword('messagedigest')
    tk_get_inst = CaselessKeyword('getinstance')
    tk_alg = Literal('"') + CaselessKeyword(algorithm.lower()) + Literal('"')
    tk_params = Literal('(') + tk_alg + Literal(')')
    instance = tk_mess_dig + Literal('.') + tk_get_inst + tk_params

    result = False
    try:
        matches = lang.check_grammar(instance, java_dest, LANGUAGE_SPECS,
                                     exclude)
        if not matches:
            show_unknown('Not files matched',
                         details=dict(code_dest=java_dest))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=java_dest))
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
def uses_md5_hash(java_dest: str, exclude: list = None) -> bool:
    """
    Check if code uses MD5 as hashing algorithm.

    See `REQ.150 <https://fluidattacks.com/web/en/rules/150/>`_.

    :param java_dest: Path to a Java source file or package.
    """
    result = uses_insecure_hash(java_dest, 'md5', exclude)
    return result


@level('medium')
@track
def uses_sha1_hash(java_dest: str, exclude: list = None) -> bool:
    """
    Check if code uses MD5 as hashing algorithm.

    See `REQ.150 <https://fluidattacks.com/web/en/rules/150/>`_.

    :param java_dest: Path to a Java source file or package.
    """
    result = uses_insecure_hash(java_dest, 'sha-1', exclude)
    return result


@level('medium')
@track
def uses_des_algorithm(java_dest: str, exclude: list = None) -> bool:
    """
    Check if code uses DES as encryption algorithm.

    See `REQ.149 <https://fluidattacks.com/web/en/rules/149/>`_.

    :param java_dest: Path to a Java source file or package.
    """
    result: bool = uses_insecure_cipher(java_dest, 'DES', exclude)
    return result


@level('low')
@track
def has_log_injection(java_dest: str, exclude: list = None) -> bool:
    """
    Search code injection.

    Check if the code does not neutralize or incorrectly neutralizes
    output that is written to logs.

    See `CWE-117 <https://cwe.mitre.org/data/definitions/117.html>`_.

    :param java_dest: Path to a Java source file or package.
    """
    log_variable = CaselessKeyword('log')
    log_level = oneOf('trace debug info warn error fatal')

    log_object = log_variable + Literal('.') + log_level

    tk_string = QuotedString('"')
    tk_var = Word(alphanums)

    pst = log_object + Literal('(') + tk_string + Literal('+') + tk_var
    result = False
    try:
        matches = lang.check_grammar(pst, java_dest, LANGUAGE_SPECS, exclude)
        if not matches:
            show_unknown('Not files matched',
                         details=dict(code_dest=java_dest))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=java_dest))
        return False
    for code_file, vulns in matches.items():
        if vulns:
            show_open('Code allows logs injection',
                      details=dict(file=code_file,
                                   fingerprint=lang.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns]),
                                   total_vulns=len(vulns)))
            result = True
        else:
            show_close('Code does not allow logs injection',
                       details=dict(file=code_file,
                                    fingerprint=lang.
                                    file_hash(code_file)))
    return result
