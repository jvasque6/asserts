# -*- coding: utf-8 -*-

"""RPGLE module.

This module allows to check RPGLE code vulnerabilities
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
from pyparsing import CaselessKeyword, Literal


@track
def has_dos_dow_sqlcod(rpg_dest):
    """Search DoS for using DoW SQLCOD = 0."""
    tk_dow = CaselessKeyword('dow')
    tk_sqlcod = CaselessKeyword('sqlcod')

    dos_dow_sqlcod = tk_dow + tk_sqlcod + Literal('=') + Literal('0')

    result = False
    matches = code_helper.check_grammar(dos_dow_sqlcod, rpg_dest, '.rpg')
    for code_file, vulns in matches.items():
        if vulns:
            show_open('Code has DoS for using "DoW SQLCOD = 0"',
                      details='File: {}, Lines: {}'.
                      format(code_file, ",".join([str(x) for x in vulns])))
            result = True
        else:
            show_close('Code does not have DoS for using "DoW SQLCOD = 0"',
                       details='File: {}'.format(code_file))
    return result
