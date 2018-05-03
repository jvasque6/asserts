# -*- coding: utf-8 -*-

"""
RPGLE module.

This module allows to check RPGLE code vulnerabilities.
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

LANGUAGE_SPECS = {
    'extensions': ['rpg', 'rpgle'],
    'block_comment_start': None,
    'block_comment_end': None,
    'line_comment': ['//', '*'],
}


@track
def has_dos_dow_sqlcod(rpg_dest):
    r"""
    Search for DoS for using ``DoW SQLCOD = 0``\ .

    :param rpg_dest: Path to a RPG source or directory.
    :rtype: bool
    """
    tk_dow = CaselessKeyword('dow')
    tk_sqlcod = CaselessKeyword('sqlcod')

    dos_dow_sqlcod = tk_dow + tk_sqlcod + Literal('=') + Literal('0')

    result = False
    matches = code_helper.check_grammar(dos_dow_sqlcod, rpg_dest,
                                        LANGUAGE_SPECS)
    for code_file, vulns in matches.items():
        if vulns:
            show_open('Code has DoS for using "DoW SQLCOD = 0"',
                      details=dict(file=code_file,
                                   fingerprint=code_helper.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns])))
            result = True
        else:
            show_close('Code does not have DoS for using "DoW SQLCOD = 0"',
                       details=dict(file=code_file,
                                    fingerprint=code_helper.
                                    file_hash(code_file)))
    return result


@track
def has_unitialized_vars(rpg_dest):
    """
    Search for unitialized variables.

    See `FLUIDDefends
    <https://fluidattacks.com/web/es/defends/rpg/inicializar-variables/>`_.

    :param rpg_dest: Path to a RPG source or directory.
    :rtype: bool
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
    matches = code_helper.check_grammar(unitialized, rpg_dest, LANGUAGE_SPECS)
    for code_file, vulns in matches.items():
        if vulns:
            show_open('Code has unitialized variables',
                      details=dict(file=code_file,
                                   fingerprint=code_helper.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns])),
                      refs='rpg/inicializar-variables/')
            result = True
        else:
            show_close('Code has not unitialized variables',
                       details=dict(file=code_file,
                                    fingerprint=code_helper.
                                    file_hash(code_file)),
                       refs='rpg/inicializar-variables/')
    return result
