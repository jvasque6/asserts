# -*- coding: utf-8 -*-

"""Test methods of fluidasserts.helper.lang."""

# standard imports
# None

# 3rd party imports
# None

# local imports
from fluidasserts.helper import lang


# Constants

LANGUAGE_SPECS = (
    ('line_comment', ('//',)),
    ('block_comment_start', '/*'),
    ('block_comment_end', '*/'),
)


def test_non_commented_code():
    """Test lang._non_commented_code."""
    result = (
        (1, '#include <stdio.h>'),
        (3, 'int main()'),
        (4, '{'),
        (5, '    '),
        (6, '    char a[] = "something" ; strncpy(buf, "but not this", 4);'),
        (12, ' printf(buf); '),
        (20, '    return 0;'),
        (21, '}'),
    )
    assert result == lang._non_commented_code('test/static/lang/c/comments.c',
                                              lang_spec=LANGUAGE_SPECS)
