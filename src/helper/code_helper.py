# -*- coding: utf-8 -*-

"""Code helper.

This module has helper functions for code modules
"""

# standard imports
import os

# 3rd party imports
# None

# local imports
from pyparsing import Or, ParseException, Literal, SkipTo


def __get_match_lines(grammar, code_file, lang_spec):
    """Check grammar in file."""
    with open(code_file) as file_fd:
        affected_lines = []
        counter = 1
        in_block_comment = False
        for line in file_fd.readlines():
            try:
                parser = ~Or(lang_spec['line_comment'])
                parser.parseString(line)
            except ParseException:
                counter += 1
                continue
            if lang_spec['block_comment_start']:
                try:
                    block_start = Literal(lang_spec['block_comment_start'])
                    parser = SkipTo(block_start) + block_start
                    parser.parseString(line)
                    counter += 1
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
                    finally:
                        counter += 1
            try:
                grammar.parseString(line)
                affected_lines.append(counter)
            except ParseException:
                pass
            finally:
                counter += 1
    return affected_lines


def check_grammar(grammar, code_dest, lang_spec):
    """Check grammar in location."""
    assert os.path.exists(code_dest)
    vulns = {}
    if os.path.isfile(code_dest):
        vulns[code_dest] = __get_match_lines(grammar, code_dest, lang_spec)
        return vulns

    for root, _, files in os.walk(code_dest):
        for code_file in files:
            full_path = os.path.join(root, code_file)
            if not full_path.split('.')[1] in lang_spec['extensions']:
                continue
            vulns[full_path] = __get_match_lines(grammar, full_path, lang_spec)
    return vulns
