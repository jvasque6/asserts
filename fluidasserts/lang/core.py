# -*- coding: utf-8 -*-

"""This module allows to check generic Code vulnerabilities."""

# standard imports
import os
import base64

# 3rd party imports
from pyparsing import Literal, Regex, Or

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
def has_text(code_dest: str, expected_text: str, exclude: list = None,
             lang_specs: dict = None) -> bool:
    """
    Check if a bad text is present in given source file.

    Search is (case-insensitively) performed by :py:func:`re.search`.

    :param code_dest: Path to the file or directory to be tested.
    :param expected_text: Bad text to look for in the file.
    """
    if not lang_specs:
        lang_specs = LANGUAGE_SPECS
    exected_regex = Regex(expected_text)
    result = False
    try:
        matches = lang.check_grammar(exected_regex, code_dest,
                                     lang_specs, exclude)
        if not matches:
            show_close('Bad text not present in code',
                       details=dict(location=code_dest,
                                    expected_text=expected_text))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist',
                     details=dict(code_dest=code_dest))
        return False
    else:
        result = True
        for code_file, vulns in matches.items():
            show_open('Bad text present in code',
                      details=dict(file=code_file,
                                   bad_text=expected_text,
                                   fingerprint=lang.
                                   file_hash(code_file),
                                   lines=str(vulns)[1:-1],
                                   total_vulns=len(vulns)))
    return result


@notify
@level('low')
@track
def has_not_text(code_dest: str, expected_text: str,
                 exclude: list = None, lang_specs: dict = None) -> bool:
    """
    Check if a required text is not present in given source file.

    Search is (case-insensitively) performed by :py:func:`re.search`.

    :param code_dest: Path to the file or directory to be tested.
    :param expected_text: Bad text to look for in the file.
    """
    if not lang_specs:
        lang_specs = LANGUAGE_SPECS
    exected_regex = Regex(expected_text)
    result = True
    try:
        matches = lang.check_grammar(exected_regex, code_dest,
                                     lang_specs, exclude)
        if not matches:
            show_open('Expected text not present in code',
                      details=dict(location=code_dest,
                                   expected_text=expected_text))
            return True
    except FileNotFoundError:
        show_unknown('File does not exist',
                     details=dict(code_dest=code_dest))
        return False
    else:
        result = False
        for code_file, vulns in matches.items():
            show_close('Expected text present in code',
                       details=dict(file=code_file,
                                    fingerprint=lang.
                                    file_hash(code_file)))
    return result


@notify
@level('low')
@track
def has_all_text(code_dest: str, expected_list: list,
                 exclude: list = None, lang_specs: dict = None) -> bool:
    """
    Check if a list of bad text is present in given source file.

    Search is (case-insensitively) performed by :py:func:`re.search`.

    :param code_dest: Path to the file or directory to be tested.
    :param expected_text: Bad text to look for in the file.
    """
    if not lang_specs:
        lang_specs = LANGUAGE_SPECS
    matches = {}
    for expected in expected_list:
        exected_regex = Regex(expected)
        result = False
        try:
            __matches = lang.check_grammar(exected_regex, code_dest,
                                           lang_specs, exclude)
            try:
                matches = {x: matches[x] + y for x, y in __matches.items()}
            except KeyError:
                matches.update(__matches)
        except FileNotFoundError:
            show_unknown('File does not exist',
                         details=dict(code_dest=code_dest))
            return False
    if not matches:
        show_close('All bad text in list was not found in code',
                   details=dict(file=code_dest))
        return False
    result = True
    for code_file, vulns in matches.items():
        show_open('A bad text from list was found in code',
                  details=dict(file=code_file,
                               fingerprint=lang.
                               file_hash(code_file),
                               text_list=expected_list,
                               lines=str(vulns)[1:-1],
                               total_vulns=len(vulns)))
    return result


@notify
@level('low')
@track
def has_any_text(code_dest: str, expected_list: list,
                 exclude: list = None, lang_specs: dict = None) -> bool:
    """
    Check if any on a list of bad text is present in given source file.

    Search is (case-insensitively) performed by :py:func:`re.search`.

    :param code_dest: Path to the file or directory to be tested.
    :param expected_text: Bad text to look for in the file.
    """
    if not lang_specs:
        lang_specs = LANGUAGE_SPECS
    matches = {}
    any_list = [Regex(expected) for expected in expected_list]
    any_query = Or(any_list)
    try:
        matches = lang.check_grammar(any_query, code_dest,
                                     lang_specs, exclude)
        if not matches:
            show_close('None of the expected strings were found in code',
                       details=dict(location=code_dest,
                                    expected_text=expected_list))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist',
                     details=dict(code_dest=code_dest))
        return False
    else:
        result = True
        for code_file, vulns in matches.items():
            show_open('Any of the expected bad text is present in code',
                      details=dict(file=code_file,
                                   expected_list=expected_list,
                                   fingerprint=lang.
                                   file_hash(code_file)))
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
@level('medium')
@track
def has_weak_cipher(code_dest: str, expected_text: str,
                    exclude: list = None, lang_specs: dict = None) -> bool:
    """
    Check if code uses base 64 to cipher confidential data.

    See `REQ.185 <https://fluidattacks.com/web/en/rules/185/>`_.

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
def has_secret(code_dest: str, secret: str, exclude: list = None,
               lang_specs: dict = None) -> bool:
    """
    Check if a secret is present in given source file.

    Search is (case-insensitively) performed by :py:func:`re.search`.

    :param code_dest: Path to the file or directory to be tested.
    :param secret: Secret to look for in the file.
    :param exclude: Files to exclude.
    """
    if not lang_specs:
        lang_specs = LANGUAGE_SPECS
    result = False
    secret_regex = Regex(secret)
    try:
        matches = lang.check_grammar(secret_regex, code_dest,
                                     lang_specs, exclude)
        if not matches:
            show_close('Secret not found in code',
                       details=dict(location=code_dest))
            return False
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(location=code_dest))
        return False

    result = [{'file': f, 'lines': v, 'fingerprint': lang.file_hash(f)}
              for f, v in matches.items() if v]
    show_open('Secret found in code',
              details=dict(location=result,
                           secret=secret,
                           total_vulns=len(result)))
    return bool(result)
