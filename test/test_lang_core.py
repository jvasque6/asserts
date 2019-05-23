# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.code.code."""

# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts.lang import core


# Constants

CODE_DIR = 'test/static/lang/c/'
SECURE_CODE = CODE_DIR + 'secure.c'
INSECURE_CODE = CODE_DIR + 'insecure.c'
NON_EXISTANT_CODE = CODE_DIR + 'notexistant.c'


#
# Open tests
#


def test_has_text_open():
    """Test code has text."""
    assert core.has_text(INSECURE_CODE, 'strcpy')
    assert core.has_text(INSECURE_CODE, 'user: root; pass: password123')


def test_has_text_open_in_dir():
    """Test code has text."""
    assert core.has_text(CODE_DIR, 'strcpy')
    assert core.has_text(CODE_DIR, 'user: root; pass: password123')


def test_has_not_text_open():
    """Test code does not have text."""
    assert core.has_not_text(INSECURE_CODE, 'strncpy')
    assert core.has_not_text(CODE_DIR, 'strcpy', exclude=['test'])


def test_has_not_text_open_in_dir():
    """Test code does not have text."""
    assert core.has_not_text(CODE_DIR, 'strncpyasda')


def test_file_exists_open():
    """Check if a given file exists."""
    assert core.file_exists(INSECURE_CODE)


def test_has_weak_cipher_open():
    """Check if base64 is used to cipher confidential data."""
    assert core.has_weak_cipher(INSECURE_CODE, 'password123')


def test_has_weak_cipher_open_in_dir():
    """Check if base64 is used to cipher confidential data."""
    assert core.has_weak_cipher(CODE_DIR, 'password123')


def test_has_secret_open():
    """Code has secret."""
    assert core.has_secret(INSECURE_CODE, 'user: root; pass: password123')


def test_has_all_text_open():
    """Check if code has all of the text in list given."""
    assert core.has_all_text(INSECURE_CODE, ['char user', 'char pass'])


def test_has_any_text_open():
    """Check if code has some of the text in list given."""
    assert core.has_any_text(INSECURE_CODE, ['char user', 'char pass'])

#
# Closing tests
#


def test_has_text_close():
    """Test code has text."""
    assert not core.has_text(SECURE_CODE, 'strcpy')
    assert not core.has_text(CODE_DIR, 'strcpy', exclude=['test'])
    assert not core.has_text(NON_EXISTANT_CODE, 'strcpy')
    assert not core.has_text(SECURE_CODE, 'user: root; pass: password123')


def test_has_not_text_close():
    """Test code does not have text."""
    assert not core.has_not_text(SECURE_CODE, 'strncpy')
    assert not core.has_not_text(NON_EXISTANT_CODE, 'strncpy')


def test_file_exists_close():
    """Check if a given file exists."""
    assert not core.file_exists('notexistingfile.code')


def test_has_weak_cipher_close():
    """Check if base64 is used to cipher confidential data."""
    assert not core.has_weak_cipher(SECURE_CODE, 'password123')
    assert not core.has_weak_cipher(CODE_DIR, 'password123', exclude=['test'])
    assert not core.has_weak_cipher(NON_EXISTANT_CODE, 'password123')


def test_has_secret_close():
    """Code has secret."""
    assert not core.has_secret(NON_EXISTANT_CODE, 'password123')
    assert not core.has_secret(SECURE_CODE, 'user: root; pass: password123')


def test_has_all_text_close():
    """Check if code has all of the text in list given."""
    assert not core.has_all_text(NON_EXISTANT_CODE,
                                 ['char user', 'char pass'])
    assert not core.has_all_text(INSECURE_CODE,
                                 ['char notu', 'char notp'])


def test_has_any_text_close():
    """Check if code has some of the text in list given."""
    assert not core.has_any_text(NON_EXISTANT_CODE,
                                 ['char user', 'char pass'])
    assert not core.has_any_text(INSECURE_CODE,
                                 ['char notu', 'char notp'])
