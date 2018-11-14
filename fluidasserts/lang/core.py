# -*- coding: utf-8 -*-

"""This module allows to check generic Code vulnerabilities."""

# standard imports
import os
import base64
from typing import Dict, List

# 3rd party imports
from pyparsing import Literal, Regex

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts import show_unknown
from fluidasserts.helper import lang
from fluidasserts.utils.decorators import track, level


LANGUAGE_SPECS = {}  # type: dict


def _generic_lang_assert(code_file: str,
                         expected_regex: str) -> Dict[str, List[str]]:
    """
    Check if a text is present in given source file.

    Search is (case-insensitively) performed by :py:func:`re.search`.

    :param code_file: Path to the file to be tested.
    :param expected_text: Bad text to look for in the file.
    """
    exp_gram = Regex(expected_regex)
    vulns = lang.check_grammar(exp_gram, code_file, LANGUAGE_SPECS)
    return vulns


def _show_has_text(vulns: Dict[str, List[str]], code_file: str,
                   expected_text: str) -> None:
    """
    Show open or close according to ``vulns`` dictionary.

    :param vulns: Vulnerabilities found, if none is empty.
    :param code_file: Path to the file.
    :param expected_text: Bad text to look for in the file.
    """
    lines = vulns[code_file]
    if lines:
        show_open('Bad text present in code',
                  details=dict(file=code_file,
                               fingerprint=lang.file_hash(code_file),
                               bad_text=expected_text,
                               lines=", ".join(
                                   [str(x) for x in lines]),
                               total_vulns=len(vulns)))
    else:
        show_close('Bad text not present in code',
                   details=dict(file=code_file,
                                fingerprint=lang.file_hash(code_file),
                                bad_text=expected_text))


def _show_has_not_text(vulns: Dict[str, List[str]], code_file: str,
                       expected_text: str) -> None:
    """
    Show open or close according to ``vulns`` dictionary.

    :param vulns: Vulnerabilities found, if none is empty.
    :param code_file: Path to the file.
    :param expected_text: Bad text to look for in the file.
    """
    lines = vulns[code_file]
    if not lines:
        show_open('Expected text not present in code',
                  details=dict(file=code_file,
                               fingerprint=lang.file_hash(code_file),
                               expected_text=expected_text,
                               total_vulns=len(vulns)))
    else:
        show_close('Expected text present in code',
                   details=dict(file=code_file,
                                fingerprint=lang.file_hash(code_file),
                                lines=", ".join(
                                    [str(x) for x in lines]),
                                expected_text=expected_text))


@level('low')
@track
def has_text(code_dest: str, expected_text: str) -> bool:
    """
    Check if a bad text is present in given source file.

    Search is (case-insensitively) performed by :py:func:`re.search`.

    :param code_dest: Path to the file or directory to be tested.
    :param expected_text: Bad text to look for in the file.
    """
    if not os.path.exists(code_dest):
        show_unknown('File does not exist', details=dict(code_dest=code_dest))
        return False
    if os.path.isfile(code_dest):
        vulns = _generic_lang_assert(code_dest, expected_text)
        _show_has_text(vulns, code_dest, expected_text)
        return bool(vulns[code_dest])

    ret_fin = False
    for root, _, files in os.walk(code_dest):
        for code_file in files:
            full_path = os.path.join(root, code_file)
            vulns = _generic_lang_assert(full_path, expected_text)
            _show_has_text(vulns, full_path, expected_text)
            ret_fin = ret_fin or bool(vulns[full_path])
    return ret_fin


@level('low')
@track
def has_not_text(code_dest: str, expected_text: str) -> bool:
    """
    Check if a required text is not present in given source file.

    Search is (case-insensitively) performed by :py:func:`re.search`.

    :param code_dest: Path to the file or directory to be tested.
    :param expected_text: Bad text to look for in the file.
    """
    if not os.path.exists(code_dest):
        show_unknown('File does not exist', details=dict(code_dest=code_dest))
        return False
    if os.path.isfile(code_dest):
        vulns = _generic_lang_assert(code_dest, expected_text)
        _show_has_not_text(vulns, code_dest, expected_text)
        return not bool(vulns[code_dest])

    ret_fin = False
    for root, _, files in os.walk(code_dest):
        for code_file in files:
            full_path = os.path.join(root, code_file)
            vulns = _generic_lang_assert(full_path, expected_text)
            _show_has_not_text(vulns, full_path, expected_text)
            ret_fin = ret_fin or not bool(vulns[full_path])
    return ret_fin


@level('low')
@track
def file_exists(code_file: str) -> bool:
    """
    Check if the given file exists.

    :param code_file: Path to the file to be tested.
    """
    if os.path.isfile(code_file):
        show_open('File exists',
                  details=dict(path=code_file,
                               fingerprint=lang.file_hash(code_file)))
        return True
    show_close('File does not exist',
               details=dict(path=code_file,
                            fingerprint=lang.file_hash(code_file)))
    return False


@level('medium')
@track
def has_weak_cipher(code_dest: str, expected_text: str) -> bool:
    """
    Check if code uses base 64 to cipher confidential data.

    See `REQ.185 <https://fluidattacks.com/web/es/rules/185/>`_.

    :param code_dest: Path to a code source file or package.
    :param expected_text: Text that might be in source file or package
    """
    enc_text = base64.b64encode(expected_text.encode('utf-8'))
    prs_base64 = Literal(enc_text.decode('utf-8'))

    result = False
    try:
        b64_matches = lang.check_grammar(prs_base64, code_dest, LANGUAGE_SPECS)
    except FileNotFoundError:
        show_unknown('File does not exist', details=dict(code_dest=code_dest))
        return False
    for code_file, vulns in b64_matches.items():
        if vulns:
            show_open('Code has confidential data encoded in base64',
                      details=dict(expected=expected_text,
                                   file=code_file,
                                   fingerprint=lang.
                                   file_hash(code_file),
                                   lines=", ".join([str(x) for x in vulns]),
                                   total_vulns=len(vulns)))
            result = True
        else:
            show_close('Code does not have confidential data encoded in \
                base64',
                       details=dict(file=code_file,
                                    fingerprint=lang.
                                    file_hash(code_file)))
    return result
