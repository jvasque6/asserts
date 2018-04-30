# -*- coding: utf-8 -*-

"""HTML check module."""

# standard imports
import re

# 3rd party imports
from bs4 import BeautifulSoup

# local imports
from fluidasserts import show_close
from fluidasserts import show_open
from fluidasserts.utils.decorators import track


def __has_attribute(filename, selector, tag, attr, value):
    """Check attribute value.

    This method checks whether the code retrieved by the selector
    (selector) inside the file (file) has an attribute (attr) with the
    specific value (value)
    """
    handle = open(filename, 'r')
    html_doc = handle.read()
    handle.close()

    soup = BeautifulSoup(html_doc, 'html.parser')
    form = soup.select(selector)

    cache_rgx = r'<%s.+%s\s*=\s*["%s"|\'%s\'].*>' % (
        tag, attr, value, value)
    prog = re.compile('%s' % cache_rgx, flags=re.IGNORECASE)
    match = prog.search(str(form))

    return match is not None


@track
def has_not_autocomplete(filename, selector):
    """Check autocomplete attribute."""
    attr = 'autocomplete'
    value = 'off'
    has_attr = __has_attribute(
        filename, selector, '[form|input]', attr, value)

    if has_attr is False:
        result = True
        show_open('{} attribute in {}'.format(attr, filename))
    else:
        result = False
        show_close('{} attribute in {}'.format(attr, filename),
                   details=dict(value=value))
    return result


@track
def is_cacheable(filename):
    """Check if cache is posible.

    Verifies if the file (filename) has the tags
    <META HTTP-EQUIV="Pragma" CONTENT="no-cache"> and
    <META HTTP-EQUIV="Expires" CONTENT="-1">
    """
    selector = 'html'
    tag = 'meta'

    attr = 'http-equiv'
    value = 'pragma'
    has_http_equiv = __has_attribute(
        filename, selector, tag, attr, value)

    if has_http_equiv is False:
        result = True
        show_open('{} attribute in {}'.format(attr, filename),
                  details=dict(value=value))
        return result

    attr = 'content'
    value = r'no\-cache'
    has_content = __has_attribute(
        filename, selector, tag, attr, value)

    if has_content is False:
        result = True
        show_open('{} attribute in {}'.format(attr, filename),
                  details=dict(value=value))
        return result

    attr = 'http-equiv'
    value = 'expires'
    has_http_equiv = __has_attribute(
        filename, selector, tag, attr, value)

    if has_http_equiv is False:
        result = True
        show_open('{} attribute in {}'.format(attr, filename),
                  details=dict(value=value))
        return result

    attr = 'content'
    value = '-1'
    has_content = __has_attribute(
        filename, selector, tag, attr, value)

    if has_content is False:
        result = True
        show_open('{} attribute in {}'.format(attr, filename),
                  details=dict(value=value))
        return result

    result = False
    show_close('{} attribute in {}'.format(attr, filename),
               details=dict(value=value))
    return result
