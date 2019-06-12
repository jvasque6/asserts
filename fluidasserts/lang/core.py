# -*- coding: utf-8 -*-

"""This module allows to check generic Code vulnerabilities."""

# standard imports
import os
import base64

# 3rd party imports
from pyparsing import Literal, Regex, MatchFirst

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.helper import lang
from fluidasserts.utils.decorators import track, level, notify


LANGUAGE_SPECS = {}  # type: dict


@notify
@level('low')
@track
def has_text(code_dest: str, expected_text: str, use_regex: bool = False,
             exclude: list = None, lang_specs: dict = None) -> bool:
    """
    Check if a bad text is present in given source file.

    if `use_regex` equals True, Search is (case-insensitively)
    performed by :py:func:`re.search`.

    :param code_dest: Path to the file or directory to be tested.
    :param expected_text: Bad text to look for in the file.
    :param use_regex: Use regular expressions instead of literals to search.
    """
    if not lang_specs:
        lang_specs = LANGUAGE_SPECS
    grammar = Regex(expected_text) if use_regex else Literal(expected_text)
    result = False
    try:
        matches = lang.check_grammar(grammar, code_dest, lang_specs, exclude)
        if not matches:
            show_close('Bad text not present in code',
                       details=dict(location=code_dest,
                                    expected_text=expected_text,
                                    used_regular_expressions=use_regex))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist',
                     details=dict(code_dest=code_dest))
        return False
    else:
        result = True
        show_open('Bad text present in code',
                  details=dict(matched=matches,
                               bad_text=expected_text,
                               used_regular_expressions=use_regex,
                               total_vulns=len(matches)))
    return result


@notify
@level('low')
@track
def has_not_text(code_dest: str, expected_text: str, use_regex: bool = False,
                 exclude: list = None, lang_specs: dict = None) -> bool:
    """
    Check if a required text is not present in given source file.

    if `use_regex` equals True, Search is (case-insensitively)
    performed by :py:func:`re.search`.

    :param code_dest: Path to the file or directory to be tested.
    :param expected_text: Bad text to look for in the file.
    :param use_regex: Use regular expressions instead of literals to search.
    """
    if not lang_specs:
        lang_specs = LANGUAGE_SPECS
    grammar = Regex(expected_text) if use_regex else Literal(expected_text)
    result = True
    try:
        matches = lang.check_grammar(grammar, code_dest,
                                     lang_specs, exclude)
        if not matches:
            show_open('Expected text not present in code',
                      details=dict(location=code_dest,
                                   expected_text=expected_text,
                                   used_regular_expressions=use_regex))
            return True
    except FileNotFoundError:
        show_unknown('File does not exist',
                     details=dict(code_dest=code_dest))
        return False
    else:
        result = False
        show_close('Expected text present in code',
                   details=dict(matched=matches,
                                used_regular_expressions=use_regex))
    return result


@notify
@level('low')
@track
def has_all_text(code_dest: str, expected_list: list, use_regex: bool = False,
                 exclude: list = None, lang_specs: dict = None) -> bool:
    """
    Check if a list of bad text is present in given source file.

    if `use_regex` equals True, Search is (case-insensitively)
    performed by :py:func:`re.search`.

    :param code_dest: Path to the file or directory to be tested.
    :param expected_list: List of bad text to look for in the file.
    :param use_regex: Use regular expressions instead of literals to search.
    """
    # Remove duplicates
    expected_list = set(expected_list)
    if not lang_specs:
        lang_specs = LANGUAGE_SPECS
    matches = {}
    for expected in expected_list:
        grammar = Regex(expected) if use_regex else Literal(expected)
        try:
            __matches = lang.check_grammar(grammar, code_dest,
                                           lang_specs, exclude)
            if not __matches:
                show_close('Not all expected text was found in code',
                           details=dict(file=code_dest))
                return False
            matches.update(__matches)
        except FileNotFoundError:
            show_unknown('File does not exist',
                         details=dict(code_dest=code_dest,
                                      used_regular_expressions=use_regex))
            return False
    show_open('A bad text from list was found in code',
              details=dict(matched=matches,
                           text_list=expected_list,
                           used_regular_expressions=use_regex,
                           total_vulns=len(matches)))
    return True


@notify
@level('low')
@track
def has_any_text(code_dest: str, expected_list: list, use_regex: bool = False,
                 exclude: list = None, lang_specs: dict = None) -> bool:
    """
    Check if any on a list of bad text is present in given source file.

    if `use_regex` equals True, Search is (case-insensitively)
    performed by :py:func:`re.search`.

    :param code_dest: Path to the file or directory to be tested.
    :param expected_list: List of bad text to look for in the file.
    :param use_regex: Use regular expressions instead of literals to search.
    """
    # Remove duplicates
    expected_list = set(expected_list)
    if not lang_specs:
        lang_specs = LANGUAGE_SPECS
    matches = {}
    any_list = [
        Regex(expected) if use_regex else Literal(expected)
        for expected in expected_list
    ]
    any_query = MatchFirst(any_list)
    try:
        matches = lang.check_grammar(any_query, code_dest,
                                     lang_specs, exclude)
        if not matches:
            show_close('None of the expected strings were found in code',
                       details=dict(location=code_dest,
                                    expected_text=expected_list,
                                    used_regular_expressions=use_regex))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist',
                     details=dict(code_dest=code_dest))
        return False
    else:
        result = True
        show_open('Any of the expected bad text is present in code',
                  details=dict(matched=matches,
                               used_regular_expressions=use_regex))
    return result


@notify
@level('low')
@track
def file_exists(code_file: str) -> bool:
    """
    Check if the given file exists.

    :param code_file: Path to the file to be tested.
    """
    if os.path.exists(code_file):
        show_open('File exists',
                  details=dict(path=code_file,
                               fingerprint=lang.file_hash(code_file)))
        return True
    show_close('File does not exist',
               details=dict(path=code_file,
                            fingerprint=lang.file_hash(code_file)))
    return False


@notify
@level('low')
@track
def file_does_not_exist(code_file: str) -> bool:
    """
    Check if the given file does'nt exist.

    :param code_file: Path to the file to be tested.
    """
    if os.path.exists(code_file):
        show_close('File exists',
                   details=dict(path=code_file,
                                fingerprint=lang.file_hash(code_file)))
        return False
    show_open('File does not exist',
              details=dict(path=code_file,
                           fingerprint=lang.file_hash(code_file)))
    return True


@notify
@level('medium')
@track
def has_weak_cipher(code_dest: str, expected_text: str,
                    exclude: list = None, lang_specs: dict = None) -> bool:
    """
    Check if code uses base 64 to cipher confidential data.

    See `REQ.185 <https://fluidattacks.com/web/rules/185/>`_.

    :param code_dest: Path to a code source file or package.
    :param expected_text: Text that might be in source file or package
    """
    if not lang_specs:
        lang_specs = LANGUAGE_SPECS
    enc_text = base64.b64encode(expected_text.encode('utf-8'))
    prs_base64 = Literal(enc_text.decode('utf-8'))

    result = False
    try:
        b64_matches = lang.check_grammar(prs_base64, code_dest,
                                         lang_specs, exclude)
        if not b64_matches:
            show_close('Code does not have confidential data encoded in \
base64',
                       details=dict(location=code_dest))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=code_dest))
        return False
    else:
        result = True
        for code_file, vulns in b64_matches.items():
            if vulns:
                show_open('Code has confidential data encoded in base64',
                          details=dict(expected=expected_text,
                                       file=code_file,
                                       fingerprint=lang.
                                       file_hash(code_file),
                                       lines=str(vulns)[1:-1],
                                       total_vulns=len(vulns)))
    return result


@notify
@level('high')
@track
def has_secret(code_dest: str, secret: str, use_regex: bool = False,
               exclude: list = None, lang_specs: dict = None) -> bool:
    """
    Check if a secret is present in given source file.

    if `use_regex` equals True, Search is (case-insensitively)
    performed by :py:func:`re.search`.

    :param code_dest: Path to the file or directory to be tested.
    :param secret: Secret to look for in the file.
    :param use_regex: Use regular expressions instead of literals to search.
    :param exclude: Files to exclude.
    """
    if not lang_specs:
        lang_specs = LANGUAGE_SPECS
    result = False
    grammar = Regex(secret) if use_regex else Literal(secret)
    try:
        matches = lang.check_grammar(grammar, code_dest,
                                     lang_specs, exclude)
        if not matches:
            show_close('Secret not found in code',
                       details=dict(location=code_dest,
                                    used_regular_expressions=use_regex))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(location=code_dest))
        return False

    result = [{'file': f, 'lines': v, 'fingerprint': lang.file_hash(f)}
              for f, v in matches.items() if v]
    show_open('Secret found in code',
              details=dict(location=result,
                           secret=secret,
                           used_regular_expressions=use_regex,
                           total_vulns=len(result)))
    return bool(result)


@notify
@level('high')
@track
def has_any_secret(code_dest: str, secrets_list: list, use_regex: bool = False,
                   exclude: list = None, lang_specs: dict = None) -> bool:
    """
    Check if any on a list of secrets is present in given source file.

    if `use_regex` equals True, Search is (case-insensitively)
    performed by :py:func:`re.search`.

    :param code_dest: Path to the file or directory to be tested.
    :param secrets_list: List of secrets to look for in the file.
    :param use_regex: Use regular expressions instead of literals to search.
    """
    # Remove duplicates
    secrets_list = set(secrets_list)
    if not lang_specs:
        lang_specs = LANGUAGE_SPECS
    matches = {}
    any_list = [
        Regex(secret) if use_regex else Literal(secret)
        for secret in secrets_list
    ]
    any_query = MatchFirst(any_list)
    try:
        matches = lang.check_grammar(any_query, code_dest,
                                     lang_specs, exclude)
        if not matches:
            show_close('None of the expected secrets were found in code',
                       details=dict(location=code_dest,
                                    secrets_list=secrets_list,
                                    used_regular_expressions=use_regex))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist',
                     details=dict(code_dest=code_dest))
        return False
    else:
        result = True

        show_open('Some of the expected secrets are present in code',
                  details=dict(matched=matches,
                               found_secrets=matches,
                               used_regular_expressions=use_regex))
    return result
