# -*- coding: utf-8 -*-

"""Python module.

This module allows to check Python code vulnerabilities
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
                       pythonStyleComment, Suppress)

LANGUAGE_SPECS = {
    'extensions': ['py'],
    'block_comment_start': '"""',
    'block_comment_end': '"""',
    'line_comment': ['#'],
}

@track
def has_generic_exceptions(py_dest):
    """Search generic exceptions in file or dir."""
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
    """Check if catches are empty or only have comments"""
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
