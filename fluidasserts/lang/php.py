# -*- coding: utf-8 -*-

"""This module allows to check PHP code vulnerabilities."""

# standard imports
# None

# 3rd party imports
from pyparsing import (CaselessKeyword, Literal, oneOf, Regex)
# local imports
from fluidasserts.helper import lang
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track, level


LANGUAGE_SPECS = {
    'extensions': ['php', 'php4', 'php5', 'php6', 'php7'],
    'block_comment_start': '/*',
    'block_comment_end': '*/',
    'line_comment': ['#', '//']
}  # type: dict


@level('low')
@track
def has_preg_ce(php_dest: str, exclude: list = None) -> bool:
    """
    Search for preg_replace calls with '/e'.

    :param php_dest: Path to a PHP script or package.
    """
    tk_preg_func = CaselessKeyword('preg_replace')
    tk_quotes = oneOf(["'", '"'])
    tk_regex = Regex(r'.*/e\b')

    tk_preg_rce = tk_preg_func + Literal('(') + tk_quotes + tk_regex + \
        tk_quotes

    result = False
    try:
        matches = lang.check_grammar(tk_preg_rce, php_dest,
                                     LANGUAGE_SPECS, exclude)
        if not matches:
            show_unknown('Not files matched', details=dict(code_dest=php_dest))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=php_dest))
        return False
    for code_file, vulns in matches.items():
        if vulns:
            show_open('Code may allow RCE using preg_replace()',
                      details=dict(file=code_file,
                                   fingerprint=lang.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns]),
                                   total_vulns=len(vulns)))
            result = True
        else:
            show_close('Code does not allow RCE using preg_replace()',
                       details=dict(file=code_file,
                                    fingerprint=lang.
                                    file_hash(code_file)))
    return result
