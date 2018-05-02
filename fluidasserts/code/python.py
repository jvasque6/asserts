# -*- coding: utf-8 -*-

"""
Python module.

This module allows to check Python code vulnerabilities.
"""

# standard imports
# None

# 3rd party imports
from pyparsing import (CaselessKeyword, Word, Literal, Optional, alphas,
                       pythonStyleComment, Suppress)

# local imports
from fluidasserts.helper import code_helper
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track


LANGUAGE_SPECS = {
    'extensions': ['py'],
    'block_comment_start': None,
    'block_comment_end': None,
    'line_comment': ['#'],
}

@track
def has_generic_exceptions(py_dest):
    """
    Search for generic exceptions in a Python script or package.

    :param py_dest: Path to a Python script or package.
    :rtype: bool
    """
    tk_except = CaselessKeyword('except')
    generic_exception = tk_except + Literal(':')

    result = False
    matches = code_helper.check_grammar(generic_exception, py_dest,
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
def swallows_exceptions(py_dest):
    """
    Search for swallowed exceptions.

    Identifies ``except`` blocks that are either empty
    or only contain comments or the ``pass`` statement.

    :param py_dest: Path to a Python script or package.
    :rtype: bool
    """
    tk_except = CaselessKeyword('except')
    tk_word = Word(alphas) + Optional('.')
    tk_pass = Literal('pass')
    parser_exception = tk_except + \
        Optional(tk_word + Optional(Literal('as') + tk_word)) + Literal(':')
    empty_exception = (Suppress(parser_exception) + \
        tk_pass).ignore(pythonStyleComment)

    result = False
    matches = code_helper.check_grammar(parser_exception, py_dest,
                                        LANGUAGE_SPECS)
    for code_file, lines in matches.items():
        vulns = code_helper.block_contains_grammar(empty_exception, code_file,
                                                   lines)
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
