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


def has_attribute(filename, selector, tag, attr, value):
    """
    Check ``HTML`` attributes` values.

    This method checks whether the code retrieved by the selector
    (``selector``) inside the file (``filename``)
    has an attribute (``attr``) with the specific value (``value``).

    All the parameters except the filename can be Python regular expressions.

    :param filename: Path to the ``HTML`` source.
    :type filename: string
    :param selector: ``CSS`` selector to test.
    :type selector: string
    :param tag: ``HTML`` tag to search.
    :type tag: string.
    :param attr: Attribute to search.
    :type attr: string
    :param value: Value the attribute should have.
    :type value: string
    :rtype: bool
    :returns: True if attribute set as specified, False otherwise.
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
    """
    Check the autocomplete attribute.

    Check if tags ``form`` and ``input`` have the ``autocomplete``
    attribute set to ``off``.

    :param filename: Path to the ``HTML`` source.
    :type filename: string
    :param selector: CSS selector to test.
    :type selector: string
    """
    attr = 'autocomplete'
    value = 'off'
    has_attr = has_attribute(
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

    Verifies if the file has the tags::
       <META HTTP-EQUIV="Pragma" CONTENT="no-cache"> and
       <META HTTP-EQUIV="Expires" CONTENT="-1">

    :param filename: Path to the ``HTML`` source.
    :type filename: string
    """
    selector = 'html'
    tag = 'meta'

    attr = 'http-equiv'
    value = 'pragma'
    has_http_equiv = has_attribute(
        filename, selector, tag, attr, value)

    if not has_http_equiv:
        result = True
        show_open('{} attribute in {}'.format(attr, filename),
                  details=dict(value=value))
        return result

    attr = 'content'
    value = r'no\-cache'
    has_content = has_attribute(
        filename, selector, tag, attr, value)

    if not has_content:
        result = True
        show_open('{} attribute in {}'.format(attr, filename),
                  details=dict(value=value))
        return result

    attr = 'http-equiv'
    value = 'expires'
    has_http_equiv = has_attribute(
        filename, selector, tag, attr, value)

    if not has_http_equiv:
        result = True
        show_open('{} attribute in {}'.format(attr, filename),
                  details=dict(value=value))
        return result

    attr = 'content'
    value = '-1'
    has_content = has_attribute(
        filename, selector, tag, attr, value)

    if not has_content:
        result = True
        show_open('{} attribute in {}'.format(attr, filename),
                  details=dict(value=value))
        return result

    result = False
    show_close('{} attribute in {}'.format(attr, filename),
               details=dict(value=value))
    return result
