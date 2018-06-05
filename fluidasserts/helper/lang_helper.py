# -*- coding: utf-8 -*-

"""This module has helper functions for code analysis modules."""

# standard imports
import hashlib
import os
from typing import Callable, Dict, List

# 3rd party imports
from pyparsing import (Or, ParseException, Literal, SkipTo, ParseResults,
                       ParserElement)

# local imports


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


def _get_match_lines(grammar: ParserElement, code_file: str,  # noqa
                     lang_spec: dict) -> List:  # noqa
    """
    Check grammar in file.

    :param grammar: Pyparsing grammar against which file will be checked.
    :param code_file: Source code file to check.
    :param lang_spec: Contains language-specific syntax elements, such as
                       acceptable file extensions and comment delimiters.
    :return: List of lines that contain grammar matches.
    """
    with open(code_file, encoding='latin-1') as file_fd:
        affected_lines = []
        counter = 0
        in_block_comment = False
        for line in file_fd.readlines():
            counter += 1
            try:
                if lang_spec.get('line_comment'):
                    parser = ~Or(lang_spec.get('line_comment'))
                    parser.parseString(line)
            except ParseException:
                continue
            if lang_spec.get('block_comment_start'):
                try:
                    block_start = Literal(lang_spec.get('block_comment_start'))
                    parser = SkipTo(block_start) + block_start
                    parser.parseString(line)
                    in_block_comment = True
                except (ParseException, IndexError):
                    pass

                if in_block_comment and lang_spec.get('block_comment_end'):
                    try:
                        block_end = Literal(lang_spec.get('block_comment_end'))
                        parser = SkipTo(block_end) + block_end
                        parser.parseString(line, parseAll=True)
                        in_block_comment = False
                        continue
                    except ParseException:
                        continue
                    except IndexError:
                        pass
            try:
                results = grammar.searchString(line, maxMatches=1)
                if not _is_empty_result(results):
                    affected_lines.append(counter)
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
                           get_block_fn: Callable) -> List[str]:
    """
    Check block grammar.

    :param grammar: Pyparsing grammar against which file will be checked.
    :param code_dest: Source code file to check.
    :param lines: List of starting lines.
    :param get_block_fn: Function that gives block code starting at line.
    """
    vulns = []
    with open(code_dest, encoding='latin-1') as code_f:
        file_lines = [x.rstrip() for x in code_f.readlines()]
        for line in lines:
            txt = get_block_fn(file_lines, line)
            results = grammar.searchString(txt, maxMatches=1)
            if not _is_empty_result(results):
                vulns.append(line)
    return vulns


def block_contains_empty_grammar(grammar: ParserElement, code_dest: str,
                                 lines: List[str],
                                 get_block_fn: Callable) -> List[str]:
    """
    Check empty block grammar.

    :param grammar: Pyparsing grammar against which file will be checked.
    :param code_dest: Source code file to check.
    :param lines: List of starting lines.
    :param get_block_fn: Function that gives block code starting at line.
    """
    vulns = []
    with open(code_dest, encoding='latin-1') as code_f:
        file_lines = code_f.readlines()
        for line in lines:
            txt = get_block_fn(file_lines, line)
            results = grammar.searchString(txt, maxMatches=1)
            if _is_empty_result(results):
                vulns.append(line)
    return vulns


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
    except FileNotFoundError:
        pass
    return dict(sha256=sha256.hexdigest())


def check_grammar(grammar: ParserElement, code_dest: str,
                  lang_spec: dict) -> Dict[str, List[str]]:
    """
    Check grammar in location.

    :param grammar: Pyparsing grammar against which file will be checked.
    :param code_dest: File or directory to check.
    :param lang_spec: Contains language-specific syntax elements, such as
                       acceptable file extensions and comment delimiters.
    :return: Maps files to their found vulnerabilites.
    """
    assert os.path.exists(code_dest)
    vulns = {}
    if os.path.isfile(code_dest):
        vulns[code_dest] = _get_match_lines(grammar, code_dest, lang_spec)
        return vulns

    for root, _, files in os.walk(code_dest):
        for code_file in files:
            full_path = os.path.join(root, code_file)
            if lang_spec.get('extensions'):
                if code_file.split('.')[-1] in lang_spec.get('extensions'):
                    vulns[full_path] = _get_match_lines(grammar, full_path,
                                                        lang_spec)
            else:
                vulns[full_path] = _get_match_lines(grammar, full_path,
                                                    lang_spec)
    return vulns
