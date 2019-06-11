# -*- coding: utf-8 -*-

"""This module has helper functions for code analysis modules."""

# standard imports
import hashlib
import os
import re
from typing import Callable, Dict, List
from functools import lru_cache

# 3rd party imports
from pyparsing import ParserElement, ParseException, ParseResults

# local imports
# none


def _re_compile(
        literals: tuple,
        pre: str = r'',
        suf: str = r'',
        sep: str = r''):
    """Return a compiled regular expression from a tuple of literals."""
    return re.compile(f'{pre}(?:{sep.join(map(re.escape, literals))}){suf}')


def _is_empty_result(parse_result: ParseResults) -> bool:
    """
    Check if a ParseResults is empty.

    :param parse_result: ParseResults from pyparsing.
    """
    if isinstance(parse_result, ParseResults):
        if parse_result:
            return _is_empty_result(parse_result[0])
        return True
    return not bool(parse_result)


@lru_cache(maxsize=None, typed=True)  # noqa
def _non_commented_code(code_file: str, lang_spec: tuple) -> tuple:  # noqa
    """
    Walk through the file and discard comments.

    :param code_file: Source code file to check.
    :param lang_spec: Contains language-specific syntax elements, such as
                       acceptable file extensions and comment delimiters.
    :return: Tuple of non-commented (line number, line content) file contents.
    """
    lang_spec = dict(lang_spec)
    line_comment = lang_spec.get('line_comment')
    block_comment_start = lang_spec.get('block_comment_start')
    block_comment_end = lang_spec.get('block_comment_end')

    if line_comment:
        re_line_comment = _re_compile(line_comment)
        re_line_comment_ignore = _re_compile(
            line_comment, suf=r'.*$')
    if block_comment_start:
        re_block_comment_start = _re_compile(block_comment_start)
        re_block_comment_start_ignore = _re_compile(
            (block_comment_start,), suf=r'.*$')
    if block_comment_end:
        re_block_comment_end = _re_compile(block_comment_end)
        re_block_comment_end_ignore = _re_compile(
            (block_comment_end,), pre=r'^.*')
    if block_comment_start and block_comment_end:
        re_block_comment_dual = _re_compile(block_comment_end)
        re_block_comment_dual_ignore = _re_compile(
            (block_comment_start, block_comment_end,), sep=r'.*?')

    with open(code_file, encoding='latin-1') as file_fd:
        in_block_comment = False
        non_commented_lines = []
        for (counter, line) in enumerate(file_fd.read().splitlines(), start=1):
            if not in_block_comment:
                if block_comment_start and block_comment_end:
                    while re_block_comment_dual.search(line):
                        # Line has a multi line comment that starts and end
                        #   on the same line
                        # Ignore what is in between
                        line = re_block_comment_dual_ignore.sub('', line)

                if line_comment and re_line_comment.search(line):
                    # Line has a single line comment
                    # Ignore the rest of the line
                    line = re_line_comment_ignore.sub('', line)

            if block_comment_start and re_block_comment_start.search(line):
                # A block comment starts in this line
                in_block_comment = True
                # Ignore the rest of the line
                line = re_block_comment_start_ignore.sub('', line)

            if in_block_comment:
                if block_comment_end and re_block_comment_end.search(line):
                    # A block comment ends in this line
                    # Ignore what is before
                    line = re_block_comment_end_ignore.sub('', line)
                    in_block_comment = False

                    if line_comment and re_line_comment.search(line):
                        # Line has a single line comment
                        # Ignore the rest of the line
                        line = re_line_comment_ignore.sub('', line)
                else:
                    continue
            if line:
                non_commented_lines.append((counter, line))

        return tuple(non_commented_lines)


def _get_match_lines(
        grammar: ParserElement,
        code_file: str,
        lang_spec: dict) -> List[int]:  # noqa
    """
    Check grammar in file.

    :param grammar: Pyparsing grammar against which file will be checked.
    :param code_file: Source code file to check.
    :param lang_spec: Contains language-specific syntax elements, such as
                       acceptable file extensions and comment delimiters.
    :return: List of lines that contain grammar matches.
    """
    affected_lines = []
    # We need hashable arguments
    lang_spec_hashable = tuple(lang_spec.items())
    for line_number, line_content in _non_commented_code(
            code_file, lang_spec_hashable):
        try:
            results = grammar.searchString(line_content, maxMatches=1)
            if not _is_empty_result(results):
                affected_lines.append(line_number)
        except ParseException:
            pass
    return affected_lines


def lists_as_string(lists: List[List], result: ParseResults,
                    level: int) -> str:
    """
    Format ParseResults as string.

    :param lists: Nested Lists from ParseResults.
    :param result: Results from parsing.
    :param level: Depth level to control recursion.
    """
    for lst in lists:
        if isinstance(lst, list):
            result = lists_as_string(lst, result, level + 1)
        else:
            result += "\t" * int(level / 2) + lst + "\n"
    return result


def block_contains_grammar(grammar: ParserElement, code_dest: str,
                           lines: List[str],
                           get_block_fn: Callable,
                           should_have: str = '',
                           should_not_have: str = '',) -> List[str]:
    """
    Check block grammar.

    :param grammar: Pyparsing grammar against which file will be checked.
    :param code_dest: Source code file to check.
    :param lines: List of starting lines.
    :param get_block_fn: Function that gives block code starting at line.
    """
    vulns = {}
    lines = [int(x) for x in lines.split(',')]
    vuln_lines = []
    with open(code_dest, encoding='latin-1') as code_f:
        file_lines = [x.rstrip() for x in code_f.readlines()]
        for line in lines:
            txt = get_block_fn(file_lines, line)
            results = grammar.searchString(txt, maxMatches=1)
            results_str = str(results)

            is_vulnerable = True
            if _is_empty_result(results):
                is_vulnerable = False
            elif should_have and should_have not in results_str:
                is_vulnerable = False
            elif should_not_have and should_not_have in results_str:
                is_vulnerable = False

            if is_vulnerable:
                vuln_lines.append(line)

    if vuln_lines:
        vulns = {
            code_dest: {
                'lines': str(vuln_lines)[1:-1],
                'file_hash': file_hash(code_dest),
            }
        }
    return vulns


def block_contains_empty_grammar(grammar: ParserElement, code_dest: str,
                                 lines: str,
                                 get_block_fn: Callable) -> List[str]:
    """
    Check empty block grammar.

    :param grammar: Pyparsing grammar against which file will be checked.
    :param code_dest: Source code file to check.
    :param lines: List of starting lines.
    :param get_block_fn: Function that gives block code starting at line.
    """
    vulns = {}
    lines = lines = [int(x) for x in lines.split(',')]
    vuln_lines = []
    with open(code_dest, encoding='latin-1') as code_f:
        file_lines = code_f.readlines()
        for line in lines:
            txt = get_block_fn(file_lines, line)
            results = grammar.searchString(txt, maxMatches=1)
            if _is_empty_result(results):
                vuln_lines.append(line)

    if vuln_lines:
        vulns = {
            code_dest: {
                'lines': str(vuln_lines)[1:-1],
                'file_hash': file_hash(code_dest),
            }
        }
    return vulns


@lru_cache(maxsize=None, typed=True)
def file_hash(filename: str) -> dict:
    """
    Get SHA256 hash from file as a dict.

    :param filename: Path to the file to digest.
    """
    sha256 = hashlib.sha256()
    try:
        with open(filename, 'rb', buffering=0) as code_fd:
            for code_byte in iter(lambda: code_fd.read(128 * 1024), b''):
                sha256.update(code_byte)
    except (FileNotFoundError, IsADirectoryError):
        return None
    return dict(sha256=sha256.hexdigest())


def _scantree(path: str):
    """Recursively yield full paths to files for a given directory."""
    for entry in os.scandir(path):
        full_path = entry.path
        if entry.is_dir(follow_symlinks=False):
            yield from _scantree(full_path)
        else:
            yield full_path


@lru_cache(maxsize=None, typed=True)
def _full_paths_in_dir(path: str):
    """Return a cacheable tuple of full_paths to files in a dir."""
    return tuple(full_path for full_path in _scantree(path))


def _check_grammar_in_file(grammar: ParserElement, code_dest: str,
                           lang_spec: dict) -> Dict[str, List[str]]:
    """
    Check grammar in file.

    :param grammar: Pyparsing grammar against which file will be checked.
    :param code_dest: File or directory to check.
    :param lang_spec: Contains language-specific syntax elements, such as
                       acceptable file extensions and comment delimiters.
    :param exclude: Exclude files or directories with given strings
    :return: Maps files to their found vulnerabilites.
    """
    vulns = {}
    lines = []
    file_extension = code_dest.rsplit('.', 1)[-1].lower()
    lang_extensions = lang_spec.get('extensions')

    if lang_extensions:
        if file_extension in lang_extensions:
            lines = _get_match_lines(grammar, code_dest, lang_spec)
    else:
        lines = _get_match_lines(grammar, code_dest, lang_spec)
    if lines:
        vulns[code_dest] = {
            'lines': str(lines)[1:-1],
            'file_hash': file_hash(code_dest),
        }
    return vulns


def _check_grammar_in_dir(grammar: ParserElement, code_dest: str,
                          lang_spec: dict,
                          exclude: list = None) -> Dict[str, List[str]]:
    """
    Check grammar in directory.

    :param grammar: Pyparsing grammar against which file will be checked.
    :param code_dest: File or directory to check.
    :param lang_spec: Contains language-specific syntax elements, such as
                       acceptable file extensions and comment delimiters.
    :param exclude: Exclude files or directories with given strings
    :return: Maps files to their found vulnerabilites.
    """
    if not exclude:
        exclude = []
    vulns = {}
    for full_path in _full_paths_in_dir(code_dest):
        if not any(x in full_path for x in exclude):
            vulns.update(_check_grammar_in_file(grammar, full_path, lang_spec))
    return vulns


def check_grammar(grammar: ParserElement, code_dest: str,
                  lang_spec: dict,
                  exclude: list = None) -> Dict[str, List[str]]:
    """
    Check grammar in location.

    :param grammar: Pyparsing grammar against which file will be checked.
    :param code_dest: File or directory to check.
    :param lang_spec: Contains language-specific syntax elements, such as
                       acceptable file extensions and comment delimiters.
    :param exclude: Exclude files or directories with given strings
    :return: Maps files to their found vulnerabilites.
    """
    if not exclude:
        exclude = []
    vulns = {}
    try:
        open(code_dest)
    except IsADirectoryError:
        vulns = _check_grammar_in_dir(grammar, code_dest, lang_spec,
                                      exclude)
    else:
        vulns = _check_grammar_in_file(grammar, code_dest, lang_spec)
    return vulns
