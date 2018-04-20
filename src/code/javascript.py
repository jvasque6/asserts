# -*- coding: utf-8 -*-

"""JavaScript module.

This module allows to check JavaScript code vulnerabilities
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
from pyparsing import (CaselessKeyword, Literal, nestedExpr)

LANGUAGE_SPECS = {
    'extensions': ['js', 'ts'],
    'block_comment_start': '/*',
    'block_comment_end': '*/',
    'line_comment': ['//'],
}

@track
def uses_console_log(js_dest):
    """Search printStackTrace calls."""
    tk_object = CaselessKeyword('console')
    tk_pst = CaselessKeyword('log')

    pst = tk_object + Literal('.') + tk_pst + nestedExpr()

    result = False
    matches = code_helper.check_grammar(pst, js_dest, LANGUAGE_SPECS)
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
