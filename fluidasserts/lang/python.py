# -*- coding: utf-8 -*-

"""This module allows to check Python code vulnerabilities."""

# standard imports
# None

# 3rd party imports
from pyparsing import (CaselessKeyword, Word, Literal, Optional, alphas,
                       pythonStyleComment, Suppress, delimitedList, Forward,
                       SkipTo, LineEnd, indentedBlock, Group)

# local imports
from fluidasserts.helper import lang
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.utils.decorators import track, level


LANGUAGE_SPECS = {
    'extensions': ['py'],
    'block_comment_start': None,
    'block_comment_end': None,
    'line_comment': ['#']
}  # type: dict


def _get_block(file_lines, line) -> str:
    """
    Return a Python block of code beginning in line.

    :param file_lines: Lines of code
    :param line: First line of block
    """
    frst_ln = file_lines[line - 1]
    file_lines = file_lines[line - 1:]
    rem_file = "\n".join(file_lines)
    indent_stack = [len(frst_ln) - len(frst_ln.lstrip(' ')) + 1]
    prs_block = Forward()
    block_line = SkipTo(LineEnd())
    block_header = SkipTo(LineEnd())
    block_body = indentedBlock(prs_block, indent_stack)
    block_def = Group(block_header + block_body)
    # pylint: disable=pointless-statement
    prs_block << (block_def | block_line)
    block_list = prs_block.parseString(rem_file).asList()
    block_str = (lang.lists_as_string(block_list, '', 0))
    return block_str.rstrip()


@level('low')
@track
def has_generic_exceptions(py_dest: str) -> bool:
    """
    Search for generic exceptions in a Python script or package.

    :param py_dest: Path to a Python script or package.
    """
    tk_except = CaselessKeyword('except')
    generic_exception = tk_except + Literal(':')

    result = False
    try:
        matches = lang.check_grammar(generic_exception, py_dest,
                                     LANGUAGE_SPECS)
    except AssertionError:
        show_unknown('File does not exist', details=dict(code_dest=py_dest))
        return False
    for code_file, vulns in matches.items():
        if vulns:
            show_open('Code uses generic exceptions',
                      details=dict(file=code_file,
                                   fingerprint=lang.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns]),
                                   total_vulns=len(vulns)))
            result = True
        else:
            show_close('Code does not use generic exceptions',
                       details=dict(file=code_file,
                                    fingerprint=lang.
                                    file_hash(code_file)))
    return result


@level('low')
@track
def swallows_exceptions(py_dest: str) -> bool:
    """
    Search for swallowed exceptions.

    Identifies ``except`` blocks that are either empty
    or only contain comments or the ``pass`` statement.

    :param py_dest: Path to a Python script or package.
    """
    tk_except = CaselessKeyword('except')
    tk_word = Word(alphas) + Optional('.')
    tk_pass = Literal('pass')
    tk_exc_obj = tk_word + Optional(Literal('as') + tk_word)
    parser_exception = tk_except + \
        Optional('(') + \
        Optional(delimitedList(tk_exc_obj)) + \
        Optional(')') + Literal(':')
    empty_exception = (Suppress(parser_exception) +
                       tk_pass).ignore(pythonStyleComment)

    result = False
    try:
        matches = lang.check_grammar(parser_exception, py_dest,
                                     LANGUAGE_SPECS)
    except AssertionError:
        show_unknown('File does not exist', details=dict(code_dest=py_dest))
        return False
    for code_file, lines in matches.items():
        vulns = lang.block_contains_grammar(empty_exception, code_file,
                                            lines, _get_block)
        if not vulns:
            show_close('Code does not have empty catches',
                       details=dict(file=code_file,
                                    fingerprint=lang.
                                    file_hash(code_file)))
        else:
            show_open('Code has empty catches',
                      details=dict(file=code_file,
                                   fingerprint=lang.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns]),
                                   total_vulns=len(vulns)))
            result = True
    return result
