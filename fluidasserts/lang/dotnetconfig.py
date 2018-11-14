# -*- coding: utf-8 -*-

"""This module allows to check Web.config code vulnerabilities."""

# standard imports
from copy import copy

# 3rd party imports
from pyparsing import (makeXMLTags, Suppress, Or, OneOrMore, withAttribute,
                       htmlComment)

# local imports
from fluidasserts.helper import lang
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track, level


LANGUAGE_SPECS = {
    'extensions': ['config'],
    'block_comment_start': '<!--',
    'block_comment_end': '-->',
}  # type: dict


def _get_block(file_lines, line) -> str:
    """
    Return a DotNetConfig block of code beginning in line.

    :param file_lines: Lines of code
    :param line: First line of block
    """
    return "".join(file_lines[line - 1:])


@level('low')
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
    try:
        custom_headers = lang.check_grammar(tk_tag_s, webconf_dest,
                                            LANGUAGE_SPECS)
    except FileNotFoundError:
        show_unknown('File does not exist',
                     details=dict(code_dest=webconf_dest))
        return False

    tk_rem = Suppress(tk_tag_s) + OneOrMore(tk_child_tag)

    for code_file, lines in custom_headers.items():
        vulns = lang.block_contains_empty_grammar(tk_rem,
                                                  code_file, lines,
                                                  _get_block)
        if vulns:
            show_open('Header X-Powered-By is present',
                      details=dict(file=code_file,
                                   fingerprint=lang.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns])))
            result = True
        else:
            show_close('Header X-Powered-By is not present',
                       details=dict(file=code_file,
                                    fingerprint=lang.
                                    file_hash(code_file)))
    return result


@level('medium')
@track
def has_ssl_disabled(apphostconf_dest: str) -> bool:
    """
    Check if SSL is disabled in ``ApplicationHost.config``.

    Search for access tag in security section in an ``ApplicationHost.config``
    source file or package.

    :param apphostconf_dest: Path to an ``ApplicationHost.config``
                             source file or package.
    """
    tk_tag_s, _ = makeXMLTags('security')
    tk_access, _ = makeXMLTags('access')
    tag_no_comm = tk_access.ignore(htmlComment)
    tk_access_none = copy(tag_no_comm)
    tk_access_none.setParseAction(withAttribute(sslFlags='None'))
    result = False
    try:
        sec_tag = lang.check_grammar(tk_tag_s, apphostconf_dest,
                                     LANGUAGE_SPECS)
    except FileNotFoundError:
        show_unknown('File does not exist',
                     details=dict(code_dest=apphostconf_dest))
        return False

    for code_file, lines in sec_tag.items():
        access_tags = lang.block_contains_grammar(tk_access,
                                                  code_file,
                                                  lines,
                                                  _get_block)

        none_sslflags = lang.block_contains_grammar(tk_access_none,
                                                    code_file,
                                                    lines,
                                                    _get_block)
        if not access_tags or none_sslflags:
            show_open('SSL is disabled',
                      details=dict(file=code_file,
                                   fingerprint=lang.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in lines])))
            result = True
        else:
            show_close('SSL is enabled',
                       details=dict(file=code_file,
                                    fingerprint=lang.
                                    file_hash(code_file)))
    return result


@level('low')
@track
def has_debug_enabled(webconf_dest: str) -> bool:
    """
    Check if debug flag is enabled in Web.config.

    Search for debug tag in compilation section in a Web.config source file
    or package.

    :param webconf_dest: Path to a Web.config source file or package.
    """
    tk_tag_s, _ = makeXMLTags('system.web')
    tk_compilation, _ = makeXMLTags('compilation')
    tag_no_comm = tk_compilation.ignore(htmlComment)
    tk_comp_debug = copy(tag_no_comm)
    tk_comp_debug.setParseAction(withAttribute(debug='true'))
    result = False
    try:
        sysweb_tag = lang.check_grammar(tk_tag_s, webconf_dest,
                                        LANGUAGE_SPECS)
    except FileNotFoundError:
        show_unknown('File does not exist',
                     details=dict(code_dest=webconf_dest))
        return False

    for code_file, lines in sysweb_tag.items():
        debug_tags = lang.block_contains_grammar(tk_comp_debug,
                                                 code_file,
                                                 lines,
                                                 _get_block)
        if debug_tags:
            show_open('Debug is enabled',
                      details=dict(file=code_file,
                                   fingerprint=lang.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in lines])))
            result = True
        else:
            show_close('Debug is disabled',
                       details=dict(file=code_file,
                                    fingerprint=lang.
                                    file_hash(code_file)))
    return result
