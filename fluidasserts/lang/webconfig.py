# -*- coding: utf-8 -*-

"""
Web.config module.

This module allows to check Web.config code vulnerabilities
"""

# standard imports
# None

# 3rd party imports
from pyparsing import (makeXMLTags, Suppress, Or, OneOrMore, withAttribute)

# local imports
from fluidasserts.helper import lang_helper
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track


LANGUAGE_SPECS = {
    'extensions': ['config'],
    'block_comment_start': '<!--',
    'block_comment_end': '-->',
}  # type: dict


@track
def is_header_x_powered_by_present(webconf_dest: str) -> bool:
    """
    Search for X-Powered-By headers in a Web.config source file or package.

    :param webconf_dest: Path to a Web.config source file or package.
    """
    tk_tag_s, _ = makeXMLTags('customHeaders')
    tk_add_tag, _ = makeXMLTags('add')
    tk_clear_tag, _ = makeXMLTags('clear')
    tk_remove_tag, _ = makeXMLTags('remove')
    tk_remove_tag.setParseAction(withAttribute(name='X-Powered-By'))
    tk_child_tag = Or([Suppress(tk_add_tag), Suppress(tk_clear_tag),
                       tk_remove_tag])
    result = False
    custom_headers = lang_helper.check_grammar(tk_tag_s, webconf_dest,
                                               LANGUAGE_SPECS)
    tk_rem = Suppress(tk_tag_s) + OneOrMore(tk_child_tag)

    for code_file, lines in custom_headers.items():
        vulns = lang_helper.block_contains_empty_grammar(tk_rem,
                                                         code_file, lines)
        if vulns:
            show_open('Header X-Powered-By is present',
                      details=dict(file=code_file,
                                   fingerprint=lang_helper.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns])))
            result = True
        else:
            show_close('Header X-Powered-By is not present',
                       details=dict(file=code_file,
                                    fingerprint=lang_helper.
                                    file_hash(code_file)))
    return result
