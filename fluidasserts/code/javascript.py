# -*- coding: utf-8 -*-

"""
JavaScript module.

This module allows to check JavaScript code vulnerabilities.
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
from pyparsing import (CaselessKeyword, Literal, Suppress, Word,
                       alphanums, nestedExpr)

LANGUAGE_SPECS = {
    'extensions': ['js', 'ts'],
    'block_comment_start': '/*',
    'block_comment_end': '*/',
    'line_comment': ['//'],
}


@track
def uses_console_log(js_dest):
    """
    Search for ``console.log()`` calls in a JavaScript file or directory.

    :param js_dest: Path to a JavaScript source file or directory.
    :rtype: bool
    """
    tk_object = CaselessKeyword('console')
    tk_method = CaselessKeyword('log')

    clog = tk_object + Literal('.') + tk_method + Suppress(nestedExpr())

    result = False
    matches = code_helper.check_grammar(clog, js_dest, LANGUAGE_SPECS)
    for code_file, vulns in matches.items():
        if vulns:
            show_open('Code uses console.log',
                      details=dict(file=code_file,
                                   fingerprint=code_helper.
                                   file_hash(code_file),
                                   lines=vulns))
            result = True
        else:
            show_close('Code does not use console.log',
                       details=dict(file=code_file,
                                    fingerprint=code_helper.
                                    file_hash(code_file)))
    return result


@track
def uses_localstorage(js_dest):
    """
    Search for ``localStorage`` calls in a JavaScript source file or directory.

    :param js_dest: Path to a JavaScript source file or directory.
    :rtype: bool
    """
    tk_object = CaselessKeyword('localstorage')
    tk_method = Word(alphanums)

    lsto = tk_object + Literal('.') + tk_method + Suppress(nestedExpr())

    result = False
    matches = code_helper.check_grammar(lsto, js_dest, LANGUAGE_SPECS)
    for code_file, vulns in matches.items():
        if vulns:
            show_open('Code uses localStorage',
                      details=dict(file=code_file,
                                   fingerprint=code_helper.
                                   file_hash(code_file),
                                   lines=vulns))
            result = True
        else:
            show_close('Code does not use localStorage',
                       details=dict(file=code_file,
                                    fingerprint=code_helper.
                                    file_hash(code_file)))
    return result


@track
def has_insecure_randoms(js_dest):
    """
    Check if code uses ``Math.Random()``

    See `REQ.224 <https://fluidattacks.com/web/es/rules/224/>`_.

    :param js_dest: Path to a JavaScript source file or package.
    :rtype: bool
    """
    tk_class = CaselessKeyword('math')
    tk_method = CaselessKeyword('random')
    tk_params = nestedExpr()
    call_function = tk_class + Literal('.') + tk_method + Suppress(tk_params)

    result = False
    random_call = code_helper.check_grammar(call_function, js_dest,
                                            LANGUAGE_SPECS)

    for code_file, vulns in random_call.items():
        if vulns:
            show_open('Code generates insecure random numbers',
                      details=dict(file=code_file,
                                   fingerprint=code_helper.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns])))
            result = True
        else:
            show_close('Code does not generates insecure random numbers',
                       details=dict(file=code_file,
                                    fingerprint=code_helper.
                                    file_hash(code_file)))
    return result
