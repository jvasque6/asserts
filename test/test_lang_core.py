# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.code.code."""

# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts.lang import core
import fluidasserts.utils.decorators

# Constants
fluidasserts.utils.decorators.UNITTEST = True
CODE_DIR = 'test/static/lang/c/'
SECURE_CODE = CODE_DIR + 'secure.c'
INSECURE_CODE = CODE_DIR + 'insecure.c'


#
# Open tests
#


def test_has_text_open():
    """Test code has text."""
    assert core.has_text(INSECURE_CODE, 'strcpy')


def test_has_text_open_in_dir():
    """Test code has text."""
    assert core.has_text(CODE_DIR, 'strcpy')


def test_has_not_text_open():
    """Test code has not text."""
    assert core.has_not_text(INSECURE_CODE, 'strncpy')


def test_has_not_text_open_in_dir():
    """Test code has not text."""
    assert core.has_not_text(CODE_DIR, 'strncpy')


def test_file_exists_open():
    """Check if a given file exists."""
    assert core.file_exists(INSECURE_CODE)


def test_has_weak_cipher_open():
    """Check if base64 is used to cipher confidential data."""
    assert core.has_weak_cipher(INSECURE_CODE, 'password123')


def test_has_weak_cipher_open_in_dir():
    """Check if base64 is used to cipher confidential data."""
    assert core.has_weak_cipher(CODE_DIR, 'password123')

#
# Closing tests
#


def test_has_text_close():
    """Test code has text."""
    assert not core.has_text(SECURE_CODE, 'strcpy')


def test_has_not_text_close():
    """Test code has not text."""
    assert not core.has_not_text(SECURE_CODE, 'strncpy')


def test_file_exists_close():
    """Check if a given file exists."""
    assert not core.file_exists('notexistingfile.code')


def test_has_weak_cipher_close():
    """Check if base64 is used to cipher confidential data."""
    assert not core.has_weak_cipher(SECURE_CODE, 'password123')