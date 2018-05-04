# -*- coding: utf-8 -*-

"""
Code module.

This module allows to check Code vulnerabilities.
"""

# standard imports
import os
import re

# 3rd party imports
# None

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.helper import code_helper
from fluidasserts.utils.decorators import track


def generic_code_assert(code_file, expected_regex):
    """
    Check if a text is present in given source file.

    Search is (case-insensitively) performed by :py:func:`re.search`.

    :param code_file: Path to the file to be tested.
    :param expected_text: Bad text to look for in the file.
    :rtype: bool
    """
    with open(code_file) as code_fd:
        if re.search(str(expected_regex), code_fd.read(), re.IGNORECASE):
            return True
        return False


def show_has_text(is_open, code_file, expected_text):
    """
    Show open or close based in is_open param.

    :param is_open: Indicates if finding is open.
    :param code_file: Path to the file.
    :param expected_text: Bad text to look for in the file.
    :rtype: bool
    """
    if is_open:
        show_open('Bad text present in code',
                  details=dict(code_file=code_file,
                               fingerprint=code_helper.file_hash(code_file),
                               expected_text=expected_text))
    else:
        show_close('Bad text not present in code',
                   details=dict(code_file=code_file,
                                fingerprint=code_helper.file_hash(code_file),
                                expected_text=expected_text))


def show_has_not_text(is_open, code_file, expected_text):
    """
    Show open or close based in is_open param.

    :param is_open: Indicates if finding is open.
    :param code_file: Path to the file.
    :param expected_text: Bad text to look for in the file.
    :rtype: bool
    """
    if is_open:
        show_open('Expected text not present in code',
                  details=dict(code_file=code_file,
                               fingerprint=code_helper.file_hash(code_file),
                               expected_text=expected_text))
    else:
        show_close('Expected text present in code',
                   details=dict(code_file=code_file,
                                fingerprint=code_helper.file_hash(code_file),
                                expected_text=expected_text))


@track
def has_text(code_dest, expected_text):
    """
    Check if a bad text is present in given source file.

    Search is (case-insensitively) performed by :py:func:`re.search`.

    :param code_dest: Path to the file or directory to be tested.
    :param expected_text: Bad text to look for in the file.
    :rtype: bool
    """
    if os.path.isfile(code_dest):
        ret = generic_code_assert(code_dest, expected_text)
        show_has_text(ret, code_dest, expected_text)
        return ret

    ret_fin = False
    for root, _, files in os.walk(code_dest):
        for code_file in files:
            full_path = os.path.join(root, code_file)
            ret = generic_code_assert(full_path, expected_text)
            show_has_text(ret, full_path, expected_text)
            ret_fin = ret_fin or ret
    return ret_fin


@track
def has_not_text(code_dest, expected_text):
    """
    Check if a required text is not present in given source file.

    Search is (case-insensitively) performed by :py:func:`re.search`.

    :param code_dest: Path to the file or directory to be tested.
    :param expected_text: Bad text to look for in the file.
    :rtype: bool
    """
    if os.path.isfile(code_dest):
        ret = generic_code_assert(code_dest, expected_text)
        show_has_text(ret, code_dest, expected_text)
        return not ret

    ret_fin = False
    for root, _, files in os.walk(code_dest):
        for code_file in files:
            full_path = os.path.join(root, code_file)
            ret = generic_code_assert(full_path, expected_text)
            show_has_text(ret, full_path, expected_text)
            ret_fin = ret_fin or not ret
    return ret_fin


@track
def file_exists(code_file):
    """
    Check if the given file exists.

    :param code_file: Path to the file to be tested.
    :rtype: bool
    """
    if os.path.isfile(code_file):
        show_open('File exists',
                  details=dict(path=code_file,
                               fingerprint=code_helper.file_hash(code_file)))
        return True
    show_close('File does not exist',
               details=dict(path=code_file,
                            fingerprint=code_helper.file_hash(code_file)))
    return False
