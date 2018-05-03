# -*- coding: utf-8 -*-

"""Code helper.

This module has helper functions for code modules
"""

# standard imports
import hashlib
import os

# 3rd party imports
# None

# local imports
from pyparsing import Or, ParseException, Literal, SkipTo


def get_match_lines(grammar, code_file, lang_spec):  # noqa
    """Check grammar in file."""
    with open(code_file) as file_fd:
        affected_lines = []
        counter = 0
        in_block_comment = False
        for line in file_fd.readlines():
            counter += 1
            try:
                parser = ~Or(lang_spec['line_comment'])
                parser.parseString(line)
            except ParseException:
                continue
            if lang_spec['block_comment_start']:
                try:
                    block_start = Literal(lang_spec['block_comment_start'])
                    parser = SkipTo(block_start) + block_start
                    parser.parseString(line)
                    in_block_comment = True
                except (ParseException, IndexError):
                    pass

                if in_block_comment:
                    try:
                        block_end = Literal(lang_spec['block_comment_end'])
                        parser = SkipTo(block_end) + block_end
                        parser.parseString(line, parseAll=True)

                        in_block_comment = False
                        continue
                    except ParseException:
                        continue
                    except IndexError:
                        pass
            try:
                grammar.parseString(line)
                affected_lines.append(counter)
            except ParseException:
                pass
    return affected_lines


def block_contains_grammar(grammar, code_dest, lines):
    """Check block grammar."""
    vulns = []
    with open(code_dest) as code_f:
        file_lines = [x.rstrip() for x in code_f.readlines()]
        for line in lines:
            txt = "".join(file_lines[line - 1:])
            results = grammar.searchString(txt)
            if results:
                vulns.append(line)
    return vulns


def block_contains_empty_grammar(grammar, code_dest, lines):
    """Check empty block grammar."""
    vulns = []
    with open(code_dest) as code_f:
        file_lines = code_f.readlines()
        for line in lines:
            txt = "".join(file_lines[line - 1:])
            results = grammar.searchString(txt)[0]
            if not results[0]:
                vulns.append(line)
    return vulns


def file_hash(filename):
    """Get SHA256 hash from file."""
    sha256 = hashlib.sha256()
    try:
        with open(filename, 'rb', buffering=0) as code_fd:
            for code_byte in iter(lambda: code_fd.read(128 * 1024), b''):
                sha256.update(code_byte)
    except FileNotFoundError:
        pass
    return dict(sha256=sha256.hexdigest())


def check_grammar(grammar, code_dest, lang_spec):
    """Check grammar in location."""
    assert os.path.exists(code_dest)
    vulns = {}
    if os.path.isfile(code_dest):
        vulns[code_dest] = get_match_lines(grammar, code_dest, lang_spec)
        return vulns

    for root, _, files in os.walk(code_dest):
        for code_file in files:
            full_path = os.path.join(root, code_file)
            if '.' in full_path:
                if not full_path.split('.')[1] in lang_spec['extensions']:
                    continue
                vulns[full_path] = get_match_lines(grammar, full_path,
                                                   lang_spec)
    return vulns
