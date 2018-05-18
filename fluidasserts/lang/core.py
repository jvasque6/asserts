# -*- coding: utf-8 -*-

"""
Core module.

This module allows to check Code vulnerabilities.
"""

# standard imports
import os
import re
import base64

# 3rd party imports
from pyparsing import Literal

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.helper import lang_helper
from fluidasserts.utils.decorators import track


LANGUAGE_SPECS = {}


def _generic_lang_assert(code_file: str, expected_regex: str) -> bool:
    """
    Check if a text is present in given source file.

    Search is (case-insensitively) performed by :py:func:`re.search`.

    :param code_file: Path to the file to be tested.
    :param expected_text: Bad text to look for in the file.
    """
    with open(code_file) as code_fd:
        if re.search(str(expected_regex), code_fd.read(), re.IGNORECASE):
            return True
        return False


def _show_has_text(is_open: bool, code_file: str, expected_text: str) -> None:
    """
    Show open or close according to ``is_open`` parameter.

    :param is_open: Indicates if finding is open.
    :param code_file: Path to the file.
    :param expected_text: Bad text to look for in the file.
    """
    if is_open:
        show_open('Bad text present in code',
                  details=dict(code_file=code_file,
                               fingerprint=lang_helper.file_hash(code_file),
                               expected_text=expected_text))
    else:
        show_close('Bad text not present in code',
                   details=dict(code_file=code_file,
                                fingerprint=lang_helper.file_hash(code_file),
                                expected_text=expected_text))


def _show_has_not_text(is_open: bool, code_file: str,
                       expected_text: str) -> None:
    """
    Show open or close based in is_open param.

    :param is_open: Indicates if finding is open.
    :param code_file: Path to the file.
    :param expected_text: Bad text to look for in the file.
    """
    if is_open:
        show_open('Expected text not present in code',
                  details=dict(code_file=code_file,
                               fingerprint=lang_helper.file_hash(code_file),
                               expected_text=expected_text))
    else:
        show_close('Expected text present in code',
                   details=dict(code_file=code_file,
                                fingerprint=lang_helper.file_hash(code_file),
                                expected_text=expected_text))


@track
def has_text(code_dest: str, expected_text: str) -> bool:
    """
    Check if a bad text is present in given source file.

    Search is (case-insensitively) performed by :py:func:`re.search`.

    :param code_dest: Path to the file or directory to be tested.
    :param expected_text: Bad text to look for in the file.
    """
    if os.path.isfile(code_dest):
        ret = _generic_lang_assert(code_dest, expected_text)
        _show_has_text(ret, code_dest, expected_text)
        return ret

    ret_fin = False
    for root, _, files in os.walk(code_dest):
        for code_file in files:
            full_path = os.path.join(root, code_file)
            ret = _generic_lang_assert(full_path, expected_text)
            _show_has_text(ret, full_path, expected_text)
            ret_fin = ret_fin or ret
    return ret_fin


@track
def has_not_text(code_dest: str, expected_text: str) -> bool:
    """
    Check if a required text is not present in given source file.

    Search is (case-insensitively) performed by :py:func:`re.search`.

    :param code_dest: Path to the file or directory to be tested.
    :param expected_text: Bad text to look for in the file.
    """
    if os.path.isfile(code_dest):
        ret = _generic_lang_assert(code_dest, expected_text)
        _show_has_text(ret, code_dest, expected_text)
        return not ret

    ret_fin = False
    for root, _, files in os.walk(code_dest):
        for code_file in files:
            full_path = os.path.join(root, code_file)
            ret = _generic_lang_assert(full_path, expected_text)
            _show_has_text(ret, full_path, expected_text)
            ret_fin = ret_fin or not ret
    return ret_fin


@track
def file_exists(code_file: str) -> bool:
    """
    Check if the given file exists.

    :param code_file: Path to the file to be tested.
    """
    if os.path.isfile(code_file):
        show_open('File exists',
                  details=dict(path=code_file,
                               fingerprint=lang_helper.file_hash(code_file)))
        return True
    show_close('File does not exist',
               details=dict(path=code_file,
                            fingerprint=lang_helper.file_hash(code_file)))
    return False


@track
def has_weak_cipher(code_dest, expected_text):
    """
    Check if code uses base 64 to cipher confidential data.

    See `REQ.185 <https://fluidattacks.com/web/es/rules/185/>`_.

    :param code_dest: Path to a code source file or package.
    :param expected_text: Text that might be in source file or package
    :rtype: bool
    """
    enc_text = base64.b64encode(expected_text.encode('utf-8'))
    prs_base64 = Literal(enc_text.decode('utf-8'))

    result = False
    b64_matches = lang_helper.check_grammar(prs_base64, code_dest,
                                            LANGUAGE_SPECS)

    for code_file, vulns in b64_matches.items():
        if vulns:
            show_open('Code has confidential data encoded in base64',
                      details=dict(expected=expected_text,
                                   file=code_file,
                                   fingerprint=lang_helper.
                                   file_hash(code_file),
                                   lines=", ".
                                   join([str(x) for x in vulns])))
            result = True
        else:
            show_close('Code does not has confidential data encoded in base64',
                       details=dict(file=code_file,
                                    fingerprint=lang_helper.
                                    file_hash(code_file)))
    return result
