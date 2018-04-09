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
from pyparsing import (CaselessKeyword, Keyword, Literal, Word, Optional,
                       NotAny, alphas, alphanums, nums)


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


@track
def has_unitialized_vars(rpg_dest):
    """Search for unitialized variables."""
    tk_data = Keyword('D')
    tk_first = Word(alphas+"_", exact=1)
    tk_rest = Word(alphanums+"_")
    tk_vartype = Word(alphas, exact=1)
    tk_varlen = Word(nums) + Word(alphas, exact=1)
    tk_inz = CaselessKeyword('inz')
    tk_varname = tk_first + tk_rest

    unitialized = tk_data + tk_varname + Optional(tk_vartype) + \
                  Optional(tk_varlen) + Optional(Word(nums)) + NotAny(tk_inz)

    result = False
    matches = code_helper.check_grammar(unitialized, rpg_dest, '.rpg')
    for code_file, vulns in matches.items():
        if vulns:
            show_open('Code has unitialized variables',
                      details='File: {}, Lines: {}'.
                      format(code_file, ",".join([str(x) for x in vulns])))
            result = True
        else:
            show_close('Code has not unitialized variables',
                       details='File: {}'.format(code_file))
    return result
