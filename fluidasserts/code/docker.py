# -*- coding: utf-8 -*-

"""
Docker module.

This module allows to check Docker code vulnerabilities.
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
from pyparsing import Word, Literal, alphas

LANGUAGE_SPECS = {
    'extensions': None,
    'block_comment_start': None,
    'block_comment_end': None,
    'line_comment': ['#'],
}

@track
def not_pinned(file_dest):
    """
    Check if the Dockerfile uses a ``FROM:...latest`` (unpinned) base image.

    :param file_dest: Path to the Dockerfile to be tested.
    :returns: True if unpinned (bad), False if pinned (good).
    :rtype: bool
    """
    tk_from = Word('FROM')
    tk_image = Word(alphas)
    tk_version = Word('latest')

    pinned = tk_from + tk_image + Literal(':') + tk_version

    result = False
    matches = code_helper.check_grammar(pinned, file_dest, LANGUAGE_SPECS)
    for code_file, vulns in matches.items():
        if vulns:
            show_open('Dockerfile uses unpinned base image(s)',
                      details=dict(file=code_file,
                                   fingerprint=code_helper.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns])))
            result = True
        else:
            show_close('Dockerfile has pinned base image(s)',
                       details=dict(file=code_file,
                                    fingerprint=code_helper.
                                    file_hash(code_file)))
    return result
